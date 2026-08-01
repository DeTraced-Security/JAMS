#include "dns/message.hpp"

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
 
    void DNSMessage::encode_uint16(std::vector<uint8_t>& out, uint16_t v) {
        out.push_back(static_cast<uint8_t>(v >> 8));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
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
        if (!decode_name(wire, off, rr.name)) {
            return false;
        }

        if (off + 10 > wire.size()) {
            return false;
        }

        rr.type = static_cast<RRType>(read_u16(wire, off));
        off += 2;
        rr.rrclass = static_cast<RRClass>(read_u16(wire, off));
        off += 2;
        rr.ttl = read_u32(wire, off);
        off += 4;
        uint16_t rdlen = read_u16(wire, off);
        off += 2;

        size_t rdata_start = off;

        if (!decode_rdata(wire, rdata_start, rdlen, rr.type, rr.rdata)) {
            return false;
        }

        off += rdlen;
        return true;
    }

    bool DNSMessage::decode_name(std::span<const uint8_t> wire, size_t& off, std::string& out, int depth) {
        // RFC 1035 4.1.4 Infinite Pointer loop prevention
        if (depth > 10) {
            return false;
        }

        out.clear();
        bool jumped = false; // fix a pointer once followed
        size_t cur = off;

        for (;;) {
            if (cur >= wire.size()) {
                return false;
            }

            uint8_t len = wire[cur];

            if (len == 0) {
                if (!jumped) {
                    off = cur + 1;
                }

                return true;
            }

            if ((len & 0xC0) == 0xC0) {
                // Pointer
                if (cur + 1 >= wire.size()) {
                    return false;
                }

                uint16_t ptr = ((len & 0x3F) << 8) | wire[cur + 1];

                if (!jumped) {
                    off = cur + 2;
                }

                jumped = true;
                cur = ptr;

                // Recurse to decode the name at the target
                std::string rest;
                size_t ptr_off = ptr;

                if (!decode_name(wire, ptr_off, rest, depth + 1)) {
                    return false;
                }
                
                if (!out.empty() && !rest.empty()) {
                    out += '.';
                }

                out += rest;
                return true;
            }

            if ((len & 0xC0) != 0) {
                return false;
            }

            // Normal Label
            ++cur;
            
            if (cur + len > wire.size()) {
                return false;
            }

            if (!out.empty()) {
                out += '.';
            }

            out.append(reinterpret_cast<const char*>(&wire[cur]), len);
            cur += len;
        }
    }

    bool DNSMessage::decode_rdata(std::span<const uint8_t> wire, size_t& rdata_off, uint16_t rdlength, RRType type, RData& out) {
        switch (type) {
            case RRType::A: {
                if (rdlength != 4) {
                    return false;
                }

                if (rdata_off + 4 > wire.size()) {
                    return false;
                }

                RDataA a;
                std::memcpy(a.addr, &wire[rdata_off], 4);
                out = a;
                
                return true;
            }

            case RRType::AAAA: {
                if (rdlength != 16) {
                    return false;
                }

                if (rdata_off + 16 > wire.size()) {
                    return false;
                }

                RDataAAAA aaaa;
                std::memcpy(aaaa.addr, &wire[rdata_off], 16);
                out = aaaa;

                return true;
            }

            case RRType::MX: {
                if (rdlength < 3) {
                    return false;
                }

                RDataMX mx;
                mx.preference = read_u16(wire, rdata_off);
                size_t name_off = rdata_off + 2;
                
                if (!decode_name(wire, name_off, mx.exchange)) {
                    return false;
                }

                out = mx;
                return true;
            }

            case RRType::TXT: {
                RDataTXT txt;
                size_t pos = rdata_off;
                size_t end = rdata_off + rdlength;

                while (pos < end) {
                    uint8_t slen = wire[pos++];

                    if (pos + slen > end) {
                        return false;
                    }

                    txt.text.append(reinterpret_cast<const char*>(&wire[pos]), slen);
                    pos += slen;
                }

                out = txt;
                return true;
            }

            case RRType::CNAME: {
                RDataCNAME cname;
                size_t name_off = rdata_off;

                if (!decode_name(wire, name_off, cname.cname)) {
                    return false;
                }

                out = cname;
                return true;
            }

            case RRType::NS: {
                RDataNS ns;
                size_t name_off = rdata_off;

                if (!decode_name(wire, name_off, ns.nsdname)) {
                    return false;
                }

                out = ns;
                return true;
            }

            default: {
                // Unknown Type, store as TXT
                out = RDataTXT{};
                return true;
            }
        };
    }

    uint16_t DNSMessage::read_u16(std::span<const uint8_t> wire, size_t off) {
        return static_cast<uint16_t>((wire[off] << 8) | wire[off + 1]);
    }

    uint32_t DNSMessage::read_u32(std::span<const uint8_t> wire, size_t off) {
        return (static_cast<uint32_t>(wire[off]) << 24)
            |  (static_cast<uint32_t>(wire[off + 1]) << 16)
            |  (static_cast<uint32_t>(wire[off + 2]) <<  8)
            |   static_cast<uint32_t>(wire[off + 3]);
    }

    std::string RDataA::to_string() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, addr, buf, sizeof(buf));
        return buf;
    }

    std::string RDataAAAA::to_string() const {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, addr, buf, sizeof(buf));
        return buf;
    }
};
