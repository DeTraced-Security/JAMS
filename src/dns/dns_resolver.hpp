#pragma once

#include "dns_types.hpp"
#include "dns_message.hpp"
#include <liburing.h>
#include <netinet/in.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <span>
#include <unordered_map>
#include <vector>

class IoUringLoop;

namespace DNS {
    using ResolveCallback = std::function<void(ResolveResult)>;

    // OpType encoding for DNS
    //
    // We reuse the same user_data packing scheme as IoUringLoop but with a
    // dedicated range for DNS ops so completions can be routed correctly.
    //
    // user_data layout for DNS:
    //  63      60 59      48 47              0
    //  ┌────────┬──────────┬──────────────────┐
    //  │  0xD   │  DnsOp   │     txid/tag     │
    //  └────────┴──────────┴──────────────────┘
    //
    // The top nibble 0xD identifies this as a DNS completion (vs SMTP 0x0).

    enum class DNSOp : uint8_t {
        Send = 0,
        Recv = 1,
        Timeout = 2
    };

    inline uint64_t dns_encode_userdata(DNSOp op, uint16_t txid) {
        return (uint64_t{0xD} << 60) 
            | (static_cast<uint64_t>(op) << 48)
            | txid;
    }

    inline bool dns_is_completion(uint64_t ud) {
        return (ud >> 60) == 0xD;
    }

    inline DNSOp dns_decode_op(uint64_t ud) {
        return static_cast<DNSOp>(
            (ud >> 48) & 0xFFF
        );
    }

    inline uint16_t dns_decode_txid(uint64_t ud) {
        return static_cast<uint16_t>(ud & 0xFFFF);
    }

    struct PendingQuery {
        std::string name;
        RRType type;
        ResolveCallback callback;
        uint8_t retries{0};
        std::vector<uint8_t> wire;
    };

    // Async stub DNS resolver using a single UDP socket and the io_uring ring
    // owned by IoUringLoop.
    //
    // Usage:
    //   resolver.resolve("_spf.example.com", RRType::TXT,
    //       [](ResolveResult r) {
    //           if (r.status == ResolveStatus::OK) { /* use r.records */ }
    //       });
    //
    // Thread safety: single-threaded - all calls must be made from the io_uring
    // event loop thread (same as SmtpSession callbacks).
    //
    // Timeout design:
    //   Each (sendmsg + recvmsg) pair is bracketed by a linked IORING_OP_TIMEOUT.
    //   If the recvmsg doesn't complete within QUERY_TIMEOUT_NS nanoseconds, the
    //   kernel cancels it and delivers -ETIME to the recvmsg CQE.  The resolver
    //   retries once, then calls the callback with ResolveStatus::Timeout.
    //
    // TCP fallback:
    //   If the response has the TC (truncated) bit set, the query is retried over
    //   TCP.

    class DNSResolver {
        public:
            DNSResolver(const std::string& nameserver, io_uring* ring);
            ~DNSResolver();

            DNSResolver(const DNSResolver&) = delete;
            DNSResolver& operator=(const DNSResolver&) = delete;

            void resolve(const std::string& name, RRType type, ResolveCallback callback);

            void on_cqe(uint64_t user_data, int res);

            void resolve_txt(const std::string& name, ResolveCallback cb);
            void resolve_mx(const std::string& name, ResolveCallback cb);
            void resolve_a(const std::string& name, ResolveCallback cb);

        private:
            void submit_query(uint16_t txid, PendingQuery& pq);
            void arm_recv(uint16_t txid);

            uint16_t alloc_txid(); // Random, collision-free
            
            void on_send(uint16_t txid, int res);
            void on_recv(uint16_t txid, int res);
            void on_timeout(uint16_t txid);

            io_uring_sqe* get_sqe();
            void submit();

            static constexpr uint64_t QUERY_TIMEOUT_NS = 5'000'000'000ULL; // 5 Seconds
            static constexpr uint8_t MAX_RETRIES = 1;
            static constexpr size_t RECV_BUF_SIZE = 4096;

            io_uring* ring_{nullptr};
            int udp_fd_{-1};
            sockaddr_in nameserver_addr_{};

            std::mt19937 rng_;
            std::uniform_int_distribution<uint16_t> txid_dist_{1, 0xFFFF};
            std::unordered_map<uint16_t, PendingQuery> pending_;

            std::unordered_map<uint16_t, std::vector<uint8_t>> recv_buffs_;

            struct RecvCtx {
                std::vector<uint8_t> buf;
                iovec iov{};
                msghdr msg{};
                sockaddr_in src_addr{};
            };

            std::unordered_map<uint16_t, RecvCtx> recv_ctxs_;
    };
};
