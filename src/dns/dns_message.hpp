#pragma once

#include "dns_types.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace DNS {
    // Encodes and decodes DNS messages per RFC 1035 4.
    //
    // Encoding:
    //   auto wire = DnsMessage::encode_query("_spf.example.com", RRType::TXT, id);
    //   // send wire bytes over UDP
    //
    // Decoding:
    //   auto msg = DnsMessage::decode(span_of_udp_payload);
    //   if (msg) { /* use msg->answers */ }
    //
    // Name compression (RFC 1035 4.1.4):
    //   Encoded names may contain pointers (top 2 bits = 11) that reference
    //   an earlier offset in the message.  decode_name() follows these pointers
    //   with a depth limit to prevent infinite loops on malformed responses.

    class DNSMessage {
        public:
            static std::vector<uint8_t> encode_query(const std::string& name, RRType type, uint16_t id);

            static std::optional<Message> decode(std::span<const uint8_t> wire);

        private:
            static void encode_name(std::vector<uint8_t>& out, const std::string& name);
            static void encode_uint16(std::vector<uint8_t>& out, uint16_t v);
            static void encode_uint32(std::vector<uint8_t>& out, uint32_t v);

            static bool decode_header(std::span<const uint8_t> wire, size_t& off, Message& msg);
            static bool decode_question(std::span<const uint8_t> wire, size_t& off, Question& q);
            static bool decode_rr(std::span<const uint8_t> wire, size_t& off, ResourceRecord& rr);

            // sometimes DNS names are compressed
            static bool decode_name(std::span<const uint8_t> wire, size_t& off, std::string& out, int depth = 0);
            static bool decode_rdata(std::span<const uint8_t> wire, size_t& rdata_off, uint16_t rdlength, RRType type, RData& out);

            // Read big endian without advancing offset
            static uint16_t read_u16(std::span<const uint8_t> wire, size_t off);
            static uint32_t read_u32(std::span<const uint8_t> wire, size_t off);
    };
};
