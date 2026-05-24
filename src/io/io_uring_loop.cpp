#include "io_uring_loop.hpp"
#include "smtp/smtp_session.hpp"

#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
 
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <cassert>

IoUringLoop::IoUringLoop(uint16_t port, unsigned queue_depth) : port_(port) {
    io_uring_params params{};
    params.flags = 0;

    int ret = io_uring_queue_init_params(queue_depth, &ring_, &params);

    if (ret < 0) { 
        throw std::runtime_error(
            std::string("io_uring_queue_init failed: ") + strerror(-ret)
        );
    }

    ring_initialized_ = true;

    std::cout << "[io_uring] features: "
        << ((params.features & IORING_FEAT_FAST_POLL) ? "FAST_POLL " : "")
        << ((params.features & IORING_FEAT_NODROP)    ? "NODROP "    : "")
        << std::endl;

    // Initialise TLS:
    const std::string cert = "/etc/letsencrypt/live/your.mail.server/fullchain.pem";
    const std::string key = "/etc/letsencrypt/live/your.mail.server/privkey.pem";
    
    try {
        tls_ctx_ = std::make_unique<TlsContext>(cert, key);
        std::cout << "[TLS] context loaded from: " << cert << std::endl;
    } catch (const std::exception& ex) {
        std::cerr << "[TLS] ERROR: Could not load key/cert: " << ex.what() << std::endl;
        std::abort();
    }

    // Initialise DNS Resolver
    try {
        dns_resolver_ = std::make_unique<DNS::DNSResolver>("1.1.1.1", &ring_);
    } catch (const std::exception& ex) {
        std::cerr << "[DNS] WARNING: resolver failed to initialise: " << ex.what() << std::endl;
    }

    setup_listen_socket();
}

static_assert(sizeof(SMTPSession) > 0); 

IoUringLoop::~IoUringLoop() {
    if (ring_initialized_) {
        io_uring_queue_exit(&ring_);
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
        }
    }
}

void IoUringLoop::setup_listen_socket() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error(
            std::string("socket(): ") + strerror(errno)
        );
    }

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family  = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error(
            std::string("bind(): ") + strerror(errno)
        );
    }

    if (::listen(listen_fd_, SOMAXCONN) < 0) {
        throw std::runtime_error(
            std::string("listen(): ") + strerror(errno)
        );
    }

    std::cout << "[SMTP] Listening on port " << port_ << std::endl;
}

void IoUringLoop::arm_accept() {
    client_addr_len_ = sizeof(client_addr_);
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_accept(
        sqe, listen_fd_,
        reinterpret_cast<sockaddr*>(&client_addr_),
        &client_addr_len_, 0
    );

    sqe->user_data = encode_userdata(op_type::Accept, 0);
    submit();
}

void IoUringLoop::run() {
    arm_accept();

    io_uring_cqe* cqe = nullptr;

    for (;;) {
        // Block until at least one completion is ready
        int ret = io_uring_wait_cqe(&ring_, &cqe);
        if (ret < 0) {
            std::cerr << "[io_uring] wait_cqe error: " << strerror(-ret) << std::endl;
            continue;
        }

        unsigned head = 0;
        io_uring_for_each_cqe(&ring_, head, cqe) {
            uint64_t ud = cqe->user_data;
            op_type op = decode_op(ud);
            uint64_t conn_id = decode_conn_id(ud);
            int res = cqe->res;

            switch (op) {
                case op_type::Accept: 
                    on_accept(0, res);
                    break;
                case op_type::Read:
                    on_read(conn_id, res);
                    break;
                case op_type::Write:
                    on_write(conn_id, res);
                    break;
                case op_type::Close:
                    on_close(conn_id);
                    break;
            }
        }

        io_uring_cq_advance(&ring_, head);
    }
}

void IoUringLoop::on_accept(int /*fd*/, int res) {
    // Always re-arm accept first so we don't miss new connections
    arm_accept();

    if (res < 0) {
        std::cerr << "[accept] Error: " << strerror(-res) << std::endl;
        return;
    }

    int client_fd = res;
    uint64_t cid = next_conn_id++;

    // TODO: Log the new connection: Preferably with DB writes
    char ip_buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &client_addr_.sin_addr, ip_buf, sizeof(ip_buf));

    auto& buf = buffers_[cid];
    buf.fd = client_fd;
    buf.read_buf.resize(READ_BUF_SIZE);

    // queue the 220 Banner (making the session available)
    sessions_[cid] = std::make_unique<SMTPSession>(cid, ip_buf, *this);

    // Arming connection reads
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_recv(sqe, client_fd, buf.read_buf.data(), buf.read_buf.size(), 0);
    sqe->user_data = encode_userdata(op_type::Read, cid);
    submit();
}

void IoUringLoop::on_read(uint64_t conn_id, int res) {
    auto bit = buffers_.find(conn_id);
    auto sit = sessions_.find(conn_id);

    if (bit == buffers_.end() || sit == sessions_.end()) {
        return;
    }

    if (res <= 0) {
        // EOF - tear down
        if (res < 0) {
            std::cerr << "[read] conn=" << conn_id << " error: " << strerror(-res) << std::endl;
        }
        submit_close(conn_id);
        return;
    }

    std::span<uint8_t> data(bit->second.read_buf.data(), static_cast<size_t>(res));

    auto tit = tls_conns_.find(conn_id);

    if (tit != tls_conns_.end()) {
        try
        {
            auto to_send = tit->second->feed_encryption(data);
            if (!to_send.empty()) {
                submit_write(conn_id, std::move(to_send));
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "[TLS] conn=" << conn_id << " feed error: " << e.what() << std::endl;
            submit_close(conn_id);
            return;
        }
        
    } else {
        sit->second->on_data(data);
    }

    // Re-arm read
    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_recv(sqe, bit->second.fd, bit->second.read_buf.data(), bit->second.read_buf.size(), 0);
    sqe->user_data = encode_userdata(op_type::Read, conn_id);
    submit();
}

void IoUringLoop::on_write(uint64_t conn_id, int res) {
    if (res < 0) {
        std::cerr << "[write] conn=" << conn_id << " error: " << strerror(-res) << std::endl;
        submit_close(conn_id);
    }

    // Write completed and now owned by sqe-prep
}

void IoUringLoop::on_close(uint64_t conn_id) {
    auto bit = buffers_.find(conn_id);
    if (bit != buffers_.end()) {
        ::close(bit->second.fd);
        buffers_.erase(bit);
    }

    sessions_.erase(conn_id);
    tls_conns_.erase(conn_id);
    std::cout << "[close] conn=" << conn_id << std::endl;
}

void IoUringLoop::submit_write(uint64_t conn_id, std::vector<uint8_t> data) {
    auto bit = buffers_.find(conn_id);
    
    if (bit == buffers_.end()) {
        return;
    }

    auto tit = tls_conns_.find(conn_id);

    if (tit != tls_conns_.end() && tit->second->handshake_done()) {
        try {
            data = tit->second->encrypt(data);
        } catch (const std::exception& ex) {
            std::cerr << "[TLS] conn=" << conn_id << " encrypt error: " << ex.what() << std::endl;
            submit_close(conn_id);
            return;
        }
    }

    // To keep the buffer alive until a completion fires,
    // We store it on the ConnBuffer ans pass a raw pointer to io_uring
    // TODO: create a write queue
    bit->second.write_buf = std::move(data);

    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_send(sqe, bit->second.fd, bit->second.write_buf.data(), bit->second.write_buf.size(), 0);
    sqe->user_data = encode_userdata(op_type::Write, conn_id);

    submit();
}

void IoUringLoop::submit_close(uint64_t conn_id) {
    auto bit = buffers_.find(conn_id);
    if (bit == buffers_.end()) {
        return;
    }

    io_uring_sqe* sqe = get_sqe();
    io_uring_prep_close(sqe, bit->second.fd);
    sqe->user_data = encode_userdata(op_type::Close, conn_id);

    submit();
}

void IoUringLoop::upgrade_tls(uint64_t conn_id) {
    if (!tls_ctx_) {
        std::cerr << "[TLS] upgrade_tls() called but no TLS context available" << std::endl;
        submit_close(conn_id);
        return;
    }

    auto sit = sessions_.find(conn_id);
    if (sit == sessions_.end()) {
        return;
    }

    SMTPSession* session = sit->second.get();

    auto tls = std::make_unique<TlsConn>(
        tls_ctx_->new_server_ssl(),
        [session](std::span<const uint8_t> plain) {
            session->on_data(plain);
        }
    );

    std::cout << "[TLS] conn=" << conn_id << " upgrading to TLS" << std::endl;
    tls_conns_[conn_id] = std::move(tls);
}

io_uring_sqe* IoUringLoop::get_sqe() {
    io_uring_sqe* sqe = io_uring_get_sqe(&ring_);

    if (!sqe) {
        // SQ is full, we submit and try again
        io_uring_submit(&ring_);
        sqe = io_uring_get_sqe(&ring_);
        
        if(!sqe) {
            throw std::runtime_error("io_uring SQ Overflow - increase depth of the queue");
        }
    }

    return sqe;
}

void IoUringLoop::submit() {
    io_uring_submit(&ring_);
}
