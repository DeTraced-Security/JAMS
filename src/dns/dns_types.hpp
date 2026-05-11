#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace DNS {
    enum class RRType : uint16_t {
        A = 1,
        NS = 2,
        CNAME = 5,
        MX = 15,
        TXT = 16,
        AAAA = 28
    };

    enum class RRClass : uint16_t {
        IN = 1,
    };

    struct RDataA {
        uint8_t addr[4]; // IPv4
        std::string to_string() const;
    };

    struct RDataAAAA {
        uint8_t addr[16]; // IPv6
        std::string to_string() const;
    };

    struct RDataMX {
        uint16_t preference;
        std::string exchange; // the domain name
    };

    struct RDataTXT {
        std::string text;
    };

    struct RDataCNAME {
        std::string cname;
    };

    struct RDataNS {
        std::string nsdname;
    };

    using RData = std::variant<RDataA, RDataAAAA, RDataMX, RDataTXT, RDataCNAME, RDataNS>;

    struct ResourceRecord {
        std::string name;
        RRType type;
        RRClass rrclass;
        uint32_t ttl;
        RData rdata;
    };

    struct Question {
        std::string name;
        RRType qtype;
        RRClass qclass{RRClass::IN};
    };

    // Flags Field (RFC 1035 4.1.1)
    struct Flags {
        bool qr{false}; // 0=query, 1=response
        uint8_t opcode{0}; // 0=QUERY
        bool aa{false}; // authoritive answer
        bool tc{false}; // truncated TCP fallback
        bool rd{true}; // recursion desired
        bool ra{false}; // recursion available
        uint8_t rcode{0}; // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN

        static constexpr uint8_t RCODE_NOERROR = 0;
        static constexpr uint8_t RCODE_NXDOMAIN = 3;
        static constexpr uint8_t RCODE_SERVFAIL = 2;
    };

    struct Message {
        uint16_t id{0};
        Flags flags{};
        std::vector<Question> questions;
        std::vector<ResourceRecord> answers;
        std::vector<ResourceRecord> authority;
        std::vector<ResourceRecord> additional;
    };

    enum class ResolveStatus {
        OK,
        NXDomain, // name doesn't exist
        ServFail, // upstream error
        Timeout, // No Response 
        Truncated, // TC bit set, TCP retry needed
        ParseError, // malformed response
    };

    struct ResolveResult {
        ResolveStatus status{ResolveStatus::OK};
        std::vector<ResourceRecord> records;
    };
};
