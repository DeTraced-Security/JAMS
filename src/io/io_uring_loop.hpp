#pragma once

#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <span>
#include <vector>

#include "tls/tls_context.hpp"
#include "tls/tls_conn.hpp"

enum class op_type : uint8_t {
    Accept = 0,
    Read = 1,
    Write = 2,
    Close = 3
};

inline uint64_t encode_userdata(op_type op, uint64_t conn_id) {
    return (static_cast<uint64_t>(op) << 60) | (conn_id & 0x0FFF'FFFF'FFFF'FFFF);
}

inline op_type decode_op(uint64_t userdata) {
    return static_cast<op_type>(userdata >> 60);
}

inline uint64_t decode_conn_id(uint64_t userdata) {
    return userdata & 0x0FFF'FFFF'FFFF'FFFF;
}

class SMTPSession;
class TlsContext;
class TlsConn;

/**
 * Design Notes:
 * - Queue Depth of 256 gives an equal amount of ops before drain
 * - Each connection is monotonically increasing
 * - The accept loop rearms itself after every accept
 */
class IoUringLoop {
    public:
        explicit IoUringLoop(uint16_t port, unsigned queue_depth = 256);
        ~IoUringLoop();

        IoUringLoop(const IoUringLoop&) = delete;
        IoUringLoop& operator=(const IoUringLoop&) = delete;

        void run();

        void submit_write(uint64_t conn_id, std::vector<uint8_t> data);

        void submit_close(uint64_t conn_id);

        void upgrade_tls(uint64_t conn_id);

    private:
        void setup_listen_socket();
        void arm_accept();

        void on_accept(int fd, int res);
        void on_read(uint64_t conn_id, int res);
        void on_write(uint64_t conn_id, int res);
        void on_close(uint64_t conn_id);

        io_uring_sqe* get_sqe();
        void submit();

        uint16_t port_;
        int listen_fd_{-1};

        io_uring ring_{};
        bool ring_initialized_{false};

        std::unique_ptr<TlsContext> tls_ctx_;

        sockaddr_in client_addr_{};
        socklen_t client_addr_len_{sizeof(client_addr_)};

        static constexpr size_t READ_BUF_SIZE = 8192;
        struct ConnBuffer {
            std::vector<uint8_t> read_buf;
            std::vector<uint8_t> write_buf;
            int fd{-1};
        };

        uint64_t next_conn_id{1};
        std::unordered_map<uint64_t, ConnBuffer> buffers_{};
        std::unordered_map<uint64_t, std::unique_ptr<SMTPSession>> sessions_{};
        std::unordered_map<uint64_t, std::unique_ptr<TlsConn>> tls_conns_{};
};
