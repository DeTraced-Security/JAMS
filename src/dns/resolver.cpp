#include "resolver.hpp"
#include "globals.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace DNS {
    DNSResolver::DNSResolver(const std::string& nameserver, io_uring* ring) : ring_(ring), rng_(std::random_device{}()) {
        udp_fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

        if (udp_fd_ < 0) {
            logger.error("[FATAL] [DNS] socket(): " + std::string(strerror(errno)));
            throw std::runtime_error(
                std::string("[DNS] socket(): " ) + strerror(errno)
            );
        }

        nameserver_addr_.sin_family = AF_INET;
        nameserver_addr_.sin_port = htons(53);

        if (::inet_pton(AF_INET, nameserver.c_str(), &nameserver_addr_.sin_addr) != 1) {
            ::close(udp_fd_);
            logger.error("[FATAL] [DNS] Invalid nameserver address: " + nameserver);
            throw std::runtime_error("[DNS] invalid nameserver address: " + nameserver);
        }

        if (::connect(udp_fd_, reinterpret_cast<sockaddr*>(&nameserver_addr_), sizeof(nameserver_addr_)) < 0) {
            ::close(udp_fd_);
            logger.error("[FATAL] [DNS] connect(): " + std::string(strerror(errno)));
            throw std::runtime_error(std::string("[DNS] connect(): ") + strerror(errno));
        }

        logger.info("[DNS] Resovler initialised, nameserver=" + nameserver);
    }

    DNSResolver::~DNSResolver() {
        if (udp_fd_ >= 0) {
            ::close(udp_fd_);
        }
    }

    void DNSResolver::resolve(const std::string& name, RRType type, ResolveCallback cb) {
        uint16_t txid = alloc_txid();

        PendingQuery pq;
        pq.name = name;
        pq.type = type;
        pq.callback = std::move(cb);
        pq.retries = 0;
        pq.wire = DNSMessage::encode_query(name, type, txid);

        logger.info("[DNS] Query txid=" + std::to_string(txid) + " name=" + name);

        submit_query(txid, pq);
        pending_[txid] = std::move(pq);
    }

    void DNSResolver::resolve_txt(const std::string& name, ResolveCallback cb) {
        resolve(name, RRType::TXT, std::move(cb));
    }

    void DNSResolver::resolve_mx(const std::string& name, ResolveCallback cb) {
        resolve(name, RRType::MX, std::move(cb));
    }

    void DNSResolver::resolve_a(const std::string& name, ResolveCallback cb) {
        resolve(name, RRType::A, std::move(cb));
    }

    void DNSResolver::on_cqe(uint64_t user_data, int res) {
        DNSOp op = dns_decode_op(user_data);
        uint16_t txid = dns_decode_txid(user_data);

        switch (op) {
            case DNSOp::Send: {
                on_send(txid, res);
                break;
            }

            case DNSOp::Recv: {
                on_recv(txid, res);
                break;
            }

            case DNSOp::Timeout: {
                on_timeout(txid);
                break;
            }
        }
    }

    void DNSResolver::submit_query(uint16_t txid, PendingQuery& pq) {
        // SendMsg SQE
        {
            static thread_local iovec send_iov;
            static thread_local msghdr send_msg;

            send_iov.iov_base = pq.wire.data();
            send_iov.iov_len = pq.wire.size();

            std::memset(&send_msg, 0, sizeof(send_msg));
            send_msg.msg_iov = &send_iov;
            send_msg.msg_iovlen = 1;

            io_uring_sqe* sqe = get_sqe();
            io_uring_prep_sendmsg(sqe, udp_fd_, &send_msg, 0);
            sqe->user_data = dns_encode_userdata(DNSOp::Send, txid);
            sqe->flags |= IOSQE_IO_LINK;
        }

        // Timeout SQE
        {
            static thread_local __kernel_timespec ts;
            ts.tv_sec = static_cast<long long>(QUERY_TIMEOUT_NS / 1'000'000'000ULL);
            ts.tv_nsec = static_cast<long long>(QUERY_TIMEOUT_NS % 1'000'000'000ULL);

            io_uring_sqe* sqe = get_sqe();
            io_uring_prep_link_timeout(sqe, &ts, 0);
            sqe->user_data = dns_encode_userdata(DNSOp::Timeout, txid);
            sqe->flags |= IOSQE_IO_LINK; 
        }

        // Recvmsg SQE
        arm_recv(txid);

        submit();
    }

    void DNSResolver::arm_recv(uint16_t txid) {
        auto& ctx = recv_ctxs_[txid];
        ctx.buf.resize(RECV_BUF_SIZE);

        ctx.iov.iov_base = ctx.buf.data();
        ctx.iov.iov_len = ctx.buf.size();

        std::memset(&ctx.msg, 0, sizeof(ctx.msg));
        ctx.msg.msg_iov = &ctx.iov;
        ctx.msg.msg_iovlen = 1;
        ctx.msg.msg_name = &ctx.src_addr;
        ctx.msg.msg_namelen = sizeof(ctx.src_addr);

        io_uring_sqe* sqe = get_sqe();
        io_uring_prep_recvmsg(sqe, udp_fd_, &ctx.msg, 0);
        sqe->user_data = dns_encode_userdata(DNSOp::Recv, txid);
    }

    void DNSResolver::on_send(uint16_t txid, int res) {
        if (res < 0) {
            logger.error("[DNS] Send failed texid=" + std::to_string(txid) + " err=" + std::string(strerror(-res)));
        }

        auto it = pending_.find(txid);

        if (it != pending_.end()) {
            it->second.callback({ResolveStatus::ServFail, {}});
            pending_.erase(it);
            recv_ctxs_.erase(txid);
        }
    }

    void DNSResolver::on_recv(uint16_t txid, int res) {
        auto pit = pending_.find(txid);
        auto cit = recv_ctxs_.find(txid);

        if (pit == pending_.end()) {
            // Already timed out
            recv_ctxs_.erase(txid);
            return;
        }

        PendingQuery& pq = pit->second;

        if (res == -ETIME || res == -ECANCELED) {
            if (pq.retries < MAX_RETRIES) {
                logger.info("[DNS] Timeout txid=" + std::to_string(txid) + " retrying...");

                ++pq.retries;

                uint16_t new_txid = alloc_txid();
                pq.wire = DNSMessage::encode_query(pq.name, pq.type, new_txid);

                PendingQuery retry_pq = std::move(pq);
                pending_.erase(pit);
                recv_ctxs_.erase(cit);

                submit_query(new_txid, retry_pq);
                pending_[new_txid] = std::move(retry_pq);            
            } else {
                logger.error("[DNS] Query timed out txid=" + std::to_string(txid) + " name=" + pq.name);

                pq.callback({ResolveStatus::Timeout, {}});
                pending_.erase(pit);
                recv_ctxs_.erase(txid);
            }
            return;
        }

        if (res < 0) {
            pq.callback({ResolveStatus::ServFail, {}});
            pending_.erase(pit);
            recv_ctxs_.erase(txid);
            return;
        }

        if (cit == recv_ctxs_.end()) {
            pq.callback({ResolveStatus::ParseError, {}});
            pending_.erase(pit);
            return;
        }

        std::span<const uint8_t> wire(cit->second.buf.data(), static_cast<size_t>(res));
        auto msg = DNSMessage::decode(wire);

        if (!msg) {
            pq.callback({ResolveStatus::ParseError, {}});
            pending_.erase(pit);
            recv_ctxs_.erase(cit);
            return;
        }

        // Verify the response ID matches our query
        if (msg->id != txid) {
            arm_recv(txid);
            submit();
            recv_ctxs_.erase(cit);
            return;
        }

        // check the rcode
        if (msg->flags.rcode == Flags::RCODE_NXDOMAIN) {
            pq.callback({ResolveStatus::NXDomain, {}});
            pending_.erase(pit);
            recv_ctxs_.erase(cit);
            return;
        }

        if (msg->flags.rcode != Flags::RCODE_NOERROR) {
            pq.callback({ResolveStatus::ServFail, {}});
            pending_.erase(pit);
            recv_ctxs_.erase(cit);
            return;
        }

        // TC bit - truncated
        if (msg->flags.tc) {
            pq.callback({ResolveStatus::ServFail, {}});
            pending_.erase(pit);
            recv_ctxs_.erase(cit);
            return;
        }

        pq.callback({ResolveStatus::OK, std::move(msg->answers)});
        pending_.erase(pit);
        recv_ctxs_.erase(cit);
    }

    void DNSResolver::on_timeout(uint16_t txid) {
        logger.info("[DNS] Timeout SQE fired txid=" + std::to_string(txid));
    }

    uint16_t DNSResolver::alloc_txid() {
        uint16_t txid;

        do {
            txid = txid_dist_(rng_);
        } while (pending_.contains(txid));

        return txid;
    }

    io_uring_sqe* DNSResolver::get_sqe() {
        io_uring_sqe* sqe = io_uring_get_sqe(ring_);

        if (!sqe) {
            io_uring_submit(ring_);
            sqe = io_uring_get_sqe(ring_);

            if (!sqe) {
                logger.error("[FATAL] [DNS] io_uring SQ overflow");
                throw std::runtime_error("[DNS] io_uring SQ overflow");
            }
        }

        return sqe;
    }

    void DNSResolver::submit() {
        io_uring_submit(ring_);
    }
};
