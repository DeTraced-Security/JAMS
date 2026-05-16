#include "spf_checker.hpp"
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>

namespace SPF {
    std::string_view result_to_string(Result r) {
        switch (r) {
            case Result::Pass: {
                return "pass";
            }
            case Result::Fail: {
                return "fail";
            }
            case Result::Neutral: {
                return "neutral";
            }
            case Result::SoftFail: {
                return "softfail";
            }
            case Result::PermError: {
                return "permerror";
            }
            case Result::None: {
                return "none";
            }
            case Result::TempError: {
                return "temperror";
            }
        }

        return "unknown";
    }

    SPFChecker::SPFChecker(DNS::DNSResolver& resolver) : resolver_(resolver) {};

    void SPFChecker::check(
        const std::string& mail_from, const std::string& client_ip,
        const std::string& helo_domain, CheckCallback callback
    ) {
        auto state = std::make_shared<EvalState>();
        state->client_ip = client_ip;
        state->helo_domain = helo_domain;
        state->callback = std::move(callback);

        // RFC 7208 4.1 - If mail_from is empty use HELO domain
        if (mail_from.empty() || mail_from == "<>") {
            state->sender_domain = helo_domain;
        } else {
            state->sender_domain = extract_domain(mail_from);
        }

        if (state->sender_domain.empty()) {
            finish(state, Result::PermError, "couldn't extract sender domain");
            return;
        }

        std::cout << "[SPF] checking " << client_ip << " for domain=" << state->sender_domain << std::endl;

        fetch_and_eval(state->sender_domain, state);
    }

    void SPFChecker::fetch_and_eval(const std::string& domain, std::shared_ptr<EvalState> state) {
        // RFC 72008 4.6.4: Max 10 lookups
        if (state->dns_lookups >= 10) {
            finish(state, Result::PermError, "too many DNS lookups");
            return;
        }
        ++state->dns_lookups;

        resolver_.resolve_txt("_spf." + domain, [this, domain, state](DNS::ResolveResult rr) mutable {
            // Try bare domain if `_spf.` returns nothing
            // some domains publish SPF without the prefix
            if (rr.status == DNS::ResolveStatus::NXDomain) {
                // sanity check, in case lookups reach 10 before the next call
                if (state->dns_lookups >= 10) {
                    finish(state, Result::PermError, "too many DNS looksups");
                    return;
                }
                ++state->dns_lookups;

                resolver_.resolve_txt(domain, [this, domain, state](DNS::ResolveResult rr2) mutable {
                    handle_txt_response(domain, rr2, state);
                });

                return;
            }

            handle_txt_response(domain, rr, state);
        });
    }

    void SPFChecker::handle_txt_response(
        const std::string& domain, DNS::ResolveResult rr, 
        std::shared_ptr<EvalState> state
    ) {
        if (rr.status == DNS::ResolveStatus::Timeout ||
            rr.status == DNS::ResolveStatus::ServFail
        ) {

            finish(state, Result::TempError, "DNS lookup failed for: " + domain);
            return;
        }

        if (rr.status == DNS::ResolveStatus::NXDomain || rr.records.empty()) {
            finish(state, Result::None, "no SPF record for: " + domain);
            return;
        }

        // Find the SPF record amongst TXT records
        // they start with "v=spf1"
        std::string spf_txt;
        for (const auto& record : rr.records) {
            if (auto* txt = std::get_if<DNS::RDataTXT>(&record.rdata)) {
                if (txt->text.starts_with("v=spf1")) {
                    if (!spf_txt.empty()) {
                        // RFC 7208 4.5 multiple SPF records
                        finish(state, Result::PermError, "multiple SPF records for: " + domain);
                        return;
                    }
                    spf_txt = txt->text;
                }
            }
        }

        if (spf_txt.empty()) {
            finish(state, Result::None, "no SPF record found for: " + domain);
            return;
        }

        SPFRecord record;
        if (!parse_record(spf_txt, record)) {
            finish(state, Result::PermError, "Malformed SPF record for: " + domain);
            return;
        }

        // Handle redirects before evaulation
        if (!record.redirect.empty() && record.mechanisms.empty()) {
            if (state->depth >= 10) {
                finish(state, Result::PermError, "SPF Redirect depth exceeded");
                return;
            }

            ++state->depth;
            
            fetch_and_eval(record.redirect, state);
            return;
        }

        evaluate(record, state);
    }

    bool SPFChecker::parse_record(const std::string& txt, SPFRecord& out) {
        // TXT should, again, start with "v=sp1"
        std::istringstream ss(txt);
        std::string token;

        // Skip the "v=spf1" if present
        ss >> token;
        if (token != "v=spf1") {
            return false;
        }

        while (ss >> token) {
            std::string lower = token;
            // Normalise to lower, DNS loves lowercase i guess?
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            if (lower.starts_with("redirect=")) {
                out.redirect = token.substr(9);
                continue;
            }

            if (lower.starts_with("exp=")) {
                out.exp = token.substr(4);
                continue;
            }

            Mechanism mech;
            if (!parse_mechanism(token, mech)) {
                return false;
            }

            out.mechanisms.push_back(std::move(mech));
        }

        return true;
    }

    bool SPFChecker::parse_mechanism(const std::string& token, Mechanism& out) {
        size_t start = 0;

        // Extract qualifer
        if (
            !token.empty() && (
                token[0] == '+' || token[0] == '-' 
                || token[0] == '~' || token[0] == '?'
            )
        ) {
            out.qualifier = token[0];
            start = 1;
        } else {
            out.qualifier = '+'; // default - the domain should match IP, we can check this later
        }

        // split the record:
        auto colon = token.find(':', start);
        if (colon == std::string::npos) {
            out.type = token.substr(start);
            out.value = {};
        } else {
            out.type = token.substr(start, colon - start);
            out.value = token.substr(colon + 1);
        }

        // Normalise to lowercase - DNS loves lowercase
        std::transform(out.type.begin(), out.type.end(), out.type.begin(), ::tolower);

        return true;
    }

    Result SPFChecker::qualifier_to_result(char q) {
        switch (q) {
            case '+': {
                return Result::Pass;
            }
            case '-': {
                return Result::Fail;
            }
            case '~': {
                return Result::SoftFail;
            }
            case '?': {
                return Result::Neutral;
            }
            default: {
                return Result::Pass; // Again, we can host check this later
            }
        }
    }

    void SPFChecker::evaluate(const SPFRecord& record, std::shared_ptr<EvalState> state) {
        // Evaluate in order - first match first serve
        // We share the pointer to avoid dangling references in the stack frames
        auto mechs = std::make_shared<std::vector<Mechanism>>(record.mechanisms);
        eval_mechanisms_at(0, record, mechs, state);
    }

    void SPFChecker::eval_mechanisms_at(
        size_t idx, const SPFRecord& record, 
        std::shared_ptr<std::vector<Mechanism>> mechs, std::shared_ptr<EvalState> state
    ) {
        if (idx >= mechs->size()) {
            // RFC 7208 4.7 - No Match = Neutral
            finish(state, Result::Neutral, "no mechanism matched");
            return;
        }

        const Mechanism& mech = (*mechs)[idx];
        auto next = [this, idx, record, mechs, state]() mutable {
            eval_mechanisms_at(idx + 1, record, mechs, state);
        };  

        const std::string& ip = state->client_ip;

        if (mech.type == "all") {
            finish(state, qualifier_to_result(mech.qualifier), "matched 'all'");
            return;
        }

        if (mech.type == "ip4") {
            if (ipv4_matches(ip, mech.value)) {
                finish(state, qualifier_to_result(mech.qualifier), "matched ipv4: " + mech.value);
                return;
            } else {
                next();
            }

            return;
        }

        if (mech.type == "ip6") {
            if (ipv6_matches(ip, mech.value)) {
                finish(state, qualifier_to_result(mech.qualifier), "matched, ipv6: " + mech.value);
                return;
            } else {
                next();
            }

            return;
        }

        if (mech.type == "a") {
            if (state->dns_lookups >= 10) {
                finish(state, Result::PermError, "too many DNS lookups");
                return;
            }
            ++state->dns_lookups;

            std::string domain = mech.value.empty() ? state->sender_domain : mech.value;

            check_a_record(domain, mech, state, [
                this, mech, idx, record, mechs, state, next
            ](bool matched) mutable {
                if (matched) {
                    finish(state, qualifier_to_result(mech.qualifier), "matched A: " + mech.value);
                    return;
                } else {
                    next();
                }
            });

            return;
        }

        if (mech.type == "include") {
            if (mech.value.empty()) {
                finish(state, Result::PermError, "include with no domain");
                return;
            }

            if (state->depth >= 10) {
                finish(state, Result::PermError, "include depth exceeded");
                return;
            }

            // Eval included domain as it modifies our eval
            auto included_state = std::make_shared<EvalState>();

            included_state->sender_domain = mech.value;
            included_state->client_ip = state->client_ip;
            included_state->helo_domain = state->helo_domain;
            included_state->dns_lookups = state->dns_lookups;
            included_state->depth = state->depth + 1;

            included_state->callback = [this, mech, state, next, mechs, idx, record](CheckResult included) mutable {
                // RFC 7208 5.2 - include result mapping
                switch (included.result) {
                    case Result::Pass: {
                        finish(state, qualifier_to_result(mech.qualifier), "matched include: " + mech.value);
                        break;
                    }
                    case Result::Fail: {
                        // RFC says we can ignore this
                    }
                    case Result::SoftFail: {
                        // And this too
                    }
                    case Result::Neutral: {
                        next(); // include doesn't match, try next mechanism
                        break;
                    }
                    case Result::TempError: {
                        finish(state, Result::TempError, "include: " + mech.value + " temp error");
                        break;
                    }
                    default: {
                        finish(state, Result::PermError, "include: " + mech.value + " perm error");
                        break;
                    }
                }
            };

            fetch_and_eval(mech.value, included_state);
            return;
        }

        if (mech.type == "ptr") {
            next(); // We can ignore this, it's been deprecated
            return;
        }

        // TODO: Implement exists mechanism
        if (mech.type == "exits") {
            next(); // currently not being implented
            return;
        }

        finish(state, Result::PermError, "unknown mechanism: " + mech.type);
    }

    void SPFChecker::check_a_record(
        const std::string& domain, const Mechanism& mech, 
        std::shared_ptr<EvalState> state, std::function<void(bool)> on_match
    ) {
        resolver_.resolve_a(domain, 
            [this, mech, state, on_match, domain](DNS::ResolveResult rr) mutable {
                if (rr.status != DNS::ResolveStatus::OK) {
                    on_match(false);
                    return;
                }

                uint8_t pfx = prefix_len(mech.value, 32);

                for (const auto& record : rr.records) {
                    if (auto* a = std::get_if<DNS::RDataA>(&record.rdata)) {
                        char addr_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, a->addr, addr_str, sizeof(addr_str));

                        std::string cidr = std::string(addr_str) + '/' + std::to_string(pfx);

                        if (ipv4_matches(state->client_ip, cidr)) {
                            on_match(true);
                            return;
                        }
                    }
                }

                on_match(false);
        });
    }

    void SPFChecker::check_mx_record(
        const std::string& domain, const Mechanism& mech,
        std::shared_ptr<EvalState> state, std::function<void(bool)> on_match
    ) {
        resolver_.resolve_mx(domain,
            [this, mech, state, on_match](DNS::ResolveResult rr) mutable {
                if (rr.status != DNS::ResolveStatus::OK) {
                    on_match(false);
                    return;
                }

                // Collect MX exchange names
                auto exchanges = std::make_shared<std::vector<std::string>>();

                for (const auto& record : rr.records) {
                    if (auto* mx = std::get_if<DNS::RDataMX>(&record.rdata)) {
                        exchanges->push_back(mx->exchange);
                    }

                    // RFC 7208 5.4 - 10 MX max
                    if (exchanges->size() > 10) {
                        exchanges->resize(10);
                    }

                    // Resolve A records for each exchange
                    auto matched = std::make_shared<bool>(false);
                    auto pending = std::make_shared<size_t>(exchanges->size());

                    for (const auto& exchange : * exchanges) {
                        if (state->dns_lookups >= 10) {
                            on_match(false);
                            return;
                        }

                        ++state->dns_lookups;

                        check_a_record(exchange, mech, state, 
                            [matched, pending, on_match](bool m) mutable {
                                if (m) {
                                    *matched = true;
                                }

                                if (--(*pending) == 0) {
                                    on_match(*matched);
                                }
                        });
                    }
                }
        });
    }

    bool SPFChecker::ipv4_matches(const std::string& client_ip, const std::string& cidr) {
        auto slash = cidr.find('/');
        std::string base_str = (slash == std::string::npos) ? cidr : cidr.substr(0,slash);
        uint8_t prefix = (slash == std::string::npos) ? 32 : static_cast<uint8_t>(std::stoi(cidr.substr(slash + 1)));

        uint32_t client_addr{}, base_addr{};

        if (inet_pton(AF_INET, client_ip.c_str(), &client_addr) != 1) {
            return false;
        }

        if (inet_pton(AF_INET, base_str.c_str(), &base_addr) != 1) {
            return false;
        }

        client_addr = ntohl(client_addr);
        base_addr = ntohl(base_addr);

        if (prefix == 0) {
            return true;
        }

        if (prefix > 32) { // How this happens, we don't know. Assume tampering
            return false;
        }

        uint32_t mask = (prefix == 32) ? 0xFFFFFFFF : ~((1u << (32 - prefix)) - 1u);

        return (client_addr & mask) == (base_addr & mask); // If i did bit masks right, this should be true
    }

    bool SPFChecker::ipv6_matches(const std::string& client_ip, const std::string& cidr) {
        auto slash = cidr.find('/');
        std::string base_str = (slash == std::string::npos) ? cidr : cidr.substr(0,slash);
        uint8_t prefix = (slash == std::string::npos) ? 128 : static_cast<uint8_t>(std::stoi(cidr.substr(slash + 1)));

        uint8_t client_addr[16]{}, base_addr[16]{};

        if (inet_pton(AF_INET6, client_ip.c_str(), client_addr) != 1) {
            return false;
        }

        if (inet_pton(AF_INET6, base_str.c_str(), base_addr) != 1) {
            return false;
        }

        // Compare bit by bit
        int full_bytes = prefix / 8;
        int rem_bits = prefix % 8;

        if (std::memcmp(client_addr, base_addr, static_cast<size_t>(full_bytes)) != 0) {
            return false;
        }

        if (rem_bits == 0) {
            return true;
        }

        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem_bits));
        return (client_addr[full_bytes] & mask) == (base_addr[full_bytes] & mask);
    }

    std::string SPFChecker::extract_domain(const std::string& mail_from) {
        auto at = mail_from.rfind('@');

        if (at == std::string::npos) {
            return {};
        }

        std::string domain = mail_from.substr(at + 1);

        if (!domain.empty() && domain.back() == '>') {
            domain.pop_back();
        }

        return domain;
    }

    uint8_t SPFChecker::prefix_len(const std::string& cidr, uint8_t default_len) {
        auto slash = cidr.find('/');
    
        if (slash == std::string::npos) {
            return default_len;
        }

        return static_cast<uint8_t>(std::stoi(cidr.substr(slash + 1)));
    }

    void SPFChecker::finish(std::shared_ptr<EvalState> state, Result result, std::string explanation) {
        std::cout << "[SPF] result=" << result_to_string(result)
            << " domain=" << state->sender_domain
            << " ip=" << state->client_ip
            << " reason=" << explanation << std::endl;

        state->callback({result, std::move(explanation)});
    }
};
