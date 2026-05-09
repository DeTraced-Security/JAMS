#include "dns_message.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <sstream>

namespace DNS {
    std::vector<uint8_t> DNSMessage::encode_query(const std::string& name, RRType type, uint16_t id) {
        std::vector<uint8_t> out;
        out.reserve(64);

        encode_uint16(out, id);
        encode_uint16(out, 0x0100);
 
        encode_uint16(out, 1);   // QDCOUNT = 1
        encode_uint16(out, 0);   // ANCOUNT
        encode_uint16(out, 0);   // NSCOUNT
        encode_uint16(out, 0);   // ARCOUNT

        encode_name(out, name);
        encode_uint16(out, static_cast<uint16_t>(type));
        encode_uint16(out, static_cast<uint16_t>(RRClass::IN));

        return out;
    }

    void DNSMessage::encode_name(std::vector<uint8_t>& out, const std::string& name) {
        // Split on '.' and emit prefixed labels
        std::istringstream ss(name);
        std::string label;

        while (std::getline(ss, label, '.')) {
            if (label.empty()) {
                continue;
            }

            // RFC 1035
            auto len = static_cast<uint8_t>(std::min(label.size(), size_t{63}));
            out.push_back(len);
            out.insert(out.end(), label.begin(), label.begin() + len);
        }

        out.push_back(0x00); // root label
    }

    void DNSMessage::encode_uint32(std::vector<uint8_t>& out, uint32_t v) {
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    }

    std::optional<Message> DNSMessage::decode(std::span<const uint8_t> wire) {
        if (wire.size() < 12) {
            return std::nullopt;
        }

        Message msg;
        size_t off = 0;

        if (!decode_header(wire, off, msg)) {
            return std::nullopt;
        }

        uint16_t qdcount = static_cast<uint16_t>(msg.questions.capacity());
        // Re-read counts from header bytes
        uint16_t qd = read_u16(wire, 4);
        uint16_t an = read_u16(wire, 6);
        uint16_t ns = read_u16(wire, 8);
        uint16_t ar = read_u16(wire, 10);
        (void)qdcount;

        for (uint16_t i = 0; i < qd; ++i) {
            Question q;
            if (!decode_question(wire, off, q)) {
                return std::nullopt;
            }

            msg.questions.push_back(std::move(q));
        }

        auto decode_section = [&](uint16_t count, std::vector<ResourceRecord>& section) -> bool {
            for (uint16_t i = 0; i < count; i++) {
                ResourceRecord rr;
                if (!decode_rr(wire, off, rr)) {
                    return false;
                }
                section.push_back(std::move(rr));
            }

            return true;
        };

        if (!decode_section(an, msg.answers)) {
            return std::nullopt;
        }

        if (!decode_section(ns, msg.authority)) {
            return std::nullopt;
        }

        if (!decode_section(ar, msg.additional)) {
            return std::nullopt;
        }

        return msg;
    }

    bool DNSMessage::decode_header(std::span<const uint8_t> wire, size_t& off, Message& msg) {
        if (wire.size() < 12) {
            return false;
        }

        msg.id = read_u16(wire, 0);

        uint16_t flags_raw = read_u16(wire, 2);
        msg.flags.qr = (flags_raw >> 15) & 1;
        msg.flags.opcode = (flags_raw >> 11) & 0xF;
        msg.flags.aa = (flags_raw >> 10) & 1;
        msg.flags.tc = (flags_raw >> 9) & 1;
        msg.flags.rd = (flags_raw >> 8) & 1;
        msg.flags.ra = (flags_raw >> 7) & 1;
        msg.flags.rcode = flags_raw & 0xF;

        off = 12;
        return true;
    }

    bool DNSMessage::decode_question(std::span<const uint8_t> wire, size_t& off, Question& q) {
        if (!decode_name(wire, off, q.name)) {
            return false;
        }

        if (off + 4 > wire.size()) {
            return false;
        }

        q.qtype = static_cast<RRType>(read_u16(wire, off));
        off += 2;
        q.qclass = static_cast<RRClass>(read_u16(wire, off));
        off += 2;

        return true;
    }

    bool DNSMessage::decode_rr(std::span<const uint8_t> wire, size_t& off, ResourceRecord& rr) {

    }

    bool DNSMessage::decode_name(std::span<const uint8_t> wire, size_t& off, std::string& out, int depth) {

    }

    bool DNSMessage::decode_rdata(std::span<const uint8_t> wire, size_t& rdata_off, uint16_t rdlength, RRType type, RData& out) {

    }

    uint16_t DNSMessage::read_u16(std::span<const uint8_t> wire, size_t off) {

    }

    uint32_t DNSMessage::read_u32(std::span<const uint8_t> wire, size_t off) {

    }

    std::string RDataA::to_string() const {

    }

    std::string RDataAAAA::to_string() const {
        
    }
};
