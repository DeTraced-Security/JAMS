#include "dmarc_checker.hpp"
#include <algorithm>
#include <iostream>
#include <charconv>
#include <iostream>
#include <random>
#include <sstream>

namespace DMARC {
    std::string_view policy_to_string(Policy p) {
        switch (p) {
            case Policy::None: {
                return "none";
            }
            case Policy::Quarantine: {
                return "quarantine";
            }
            case Policy::Reject: {
                return "reject";
            }
        }

        return "none";
    }

    std::string_view result_to_string(Result r) {
        switch (r) {
            case Result::Fail: {
                return "fail";
            }
            case Result::None: {
                return "none";
            }
            case Result::Pass: {
                return "pass";
            }
            case Result::PermError: {
                return "permerror";
            }
            case Result::TempError: {
                return "temperror";
            }
        }

        return "none";
    }

    DMARCChecker::DMARCChecker(DNS::DNSResolver& resolver) : resolver_(resolver) {}

    void DMARCChecker::check(
        const std::string& from_domain, const std::string& mail_from_domain,
        SPF::Result spf_result, const std::vector<DKIM::VerifyResult>& dkim_results,
        CheckCallback callback
    ) {
        auto state = std::make_shared<EvalState>();
        state->from_domain = from_domain;
        state->mail_from_domain = mail_from_domain;
        state->spf_result = spf_result;
        state->dkim_results = dkim_results;
        state->callback = std::move(callback); // hand ownership to state

        std::string root_domain = org_domain(from_domain);
        std::cout << "[DMARC] checking from_domain=" << from_domain << " org_domain=" << root_domain << std::endl;

        fetch_and_evaluate("_dmarc." + root_domain, from_domain, root_domain != from_domain, state);
    }

    void DMARCChecker::fetch_and_evaluate(
        const std::string& dmarc_domain, const std::string& from_domain, 
        bool is_subdomain_fallback, std::shared_ptr<EvalState> state
    ) {
        resolver_.resolve_txt(dmarc_domain,
            [this, dmarc_domain, from_domain, is_subdomain_fallback, state](DNS::ResolveResult rr) mutable {
                if (
                    rr.status == DNS::ResolveStatus::Timeout ||
                    rr.status == DNS::ResolveStatus::ServFail
                ) {
                    finish(
                        state, Result::TempError, Policy::None, 
                        false, false, "DNS Error for: " + dmarc_domain
                    );
                    return;
                }

                // No Record found
                if (
                    rr.status == DNS::ResolveStatus::NXDomain ||
                    rr.records.empty()
                ) {
                    if (!is_subdomain_fallback) {
                        finish(
                            state, Result::None, Policy::None, 
                            false, false, "No DMARC record for: " + dmarc_domain
                        );
                        return;
                    }

                    // Fallback: directly trying the dmarc record
                    fetch_and_evaluate("_dmarc." + from_domain, from_domain, false, state);
                    return;
                }

                // Find the DMARC record "v=DMARC1"
                std::string dmarc_txt{};
                for (const auto& record : rr.records) {
                    if (auto* txt = std::get_if<DNS::RDataTXT>(&record.rdata)) {
                        if (
                            txt->text.starts_with("v=DMARC1") || 
                            txt->text.starts_with("v=dmarc1")
                        ) {
                            dmarc_txt = txt->text;
                            break;
                        }
                    }
                }

                // If the record is empty or missing
                if (dmarc_txt.empty()) {
                    finish(
                        state, Result::None, Policy::None,
                        false, false, "DMARC record not found or empty"
                    );
                    return;
                }

                auto record = parse_record(dmarc_txt);
                if (!record) {
                    finish(
                        state, Result::PermError, Policy::None,
                        false, false, "Malformed DMARC record"
                    );
                    return;
                }

                bool is_subdomain = (
                    org_domain(state->from_domain) != state->from_domain
                );
                evaluate(*record, is_subdomain, state);
            }
        );
    }

    void DMARCChecker::evaluate(const DMARCRecord& record, bool is_subdomain, std::shared_ptr<EvalState> state) {
        // Fall back to p= if there's no sp=
        const Policy used_policy = is_subdomain ? record.subdomain_policy : record.policy;

        // SPF must have passed and be aligned with the sender
        bool spf_passed = (state->spf_result == SPF::Result::Pass);
        bool spf_aligned = false;

        if (spf_passed) {
            spf_aligned = aligned(state->mail_from_domain, state->from_domain, record.aspf);
        }

        // DKIM RFC states that all signatures that align is sufficient, if passed
        bool dkim_aligned = false;
        for (const auto& dr : state->dkim_results) {
            if (dr.result == DKIM::Result::Pass) {
                if (aligned(dr.domain, state->from_domain, record.adkim)) {
                    dkim_aligned = true;
                    break;
                }
            }
        }

        bool dmarc_passed = spf_aligned || dkim_aligned;

        std::cout << "[DMARC] spf_aligned=" << spf_aligned
            << " dkim_aligned=" << dkim_aligned
            << " pass=" << dmarc_passed
            << " policy=" << policy_to_string(used_policy) << std::endl;
        
        if (dmarc_passed) {
            finish(state, Result::Pass, Policy::None, spf_aligned, dkim_aligned);
            return;
        }

        ///TODO: maybe implement sampling for that 4% when it matters
        Policy applied_policy = used_policy;

        if (used_policy != Policy::None) {
            if (record.policy == Policy::Quarantine) {
                applied_policy = Policy::Quarantine;
            } 
            if (record.policy == Policy::Reject) {
                applied_policy = Policy::Reject;
            }  
        }  

        std::string explanation = "SPF aligned: ";
        explanation += (spf_aligned ? "yes" : "no");
        explanation += ", DKIM aligned: ";
        explanation += (dkim_aligned ? "yes" : "no");

        finish(
            state, Result::Fail, applied_policy, spf_aligned, 
            dkim_aligned, explanation
        );
    }

    std::optional<DMARCRecord> DMARCChecker::parse_record(const std::string& txt) {
        DMARCRecord record;
        std::istringstream ss(txt);
        std::string token;

        while (std::getline(ss, token, ';')) {
            // Trim CRLF
            auto start = token.find_first_not_of(" \t\r\n");
            auto end   = token.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) continue;
            token = token.substr(start, end - start + 1);
    
            auto eq = token.find('=');
            if (eq == std::string::npos) continue;
    
            std::string tag = token.substr(0, eq);
            std::string value = token.substr(eq + 1);
    
            // Trim tag and value
            auto trim = [](std::string s) {
                auto a = s.find_first_not_of(" \t");
                auto b = s.find_last_not_of(" \t");
                return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
            };
            tag = trim(tag);
            value = trim(value);

            if (tag == "v") {
                // do nothing, it's already validated
            } else if (tag == "p") {
                record.policy = parse_policy(value);
            } else if (tag == "sp") {
                record.subdomain_policy = parse_policy(value);
            } else if(tag == "adkim") {
                record.adkim = value;
            } else if (tag == "aspf") {
                record.aspf = value;
            } else if (tag == "pct") {
                // ignore, we don't have it implemented
            } else if (tag == "rua") {
                record.rua = value;
            } else if (tag == "ruf") {
                record.ruf = value;
            } else if (tag == "fo") {
                record.fo = value;
            } else if (tag == "rf") {
                record.rf = value;
            } else if (tag == "ri") {
                try {
                    record.ri = static_cast<uint32_t>(std::stoul(value));
                } catch (...) {
                    // default to 86400
                    record.ri = 86400;
                }
            }
            // We can safely ignore anything else
        }

        // default sp to p if nothing is specified
        if (
            record.subdomain_policy == Policy::None &&
            record.policy != Policy::None
        ) {
            record.subdomain_policy = record.policy;
        }

        return record;
    }

    Policy DMARCChecker::parse_policy(const std::string& value) {
        // Normalise in case of mix or upper case
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower == "reject") {
            return Policy::Reject;
        }
        if (lower == "quarantine") {
            return Policy::Reject;
        }

        // if not set or is already p=none
        return Policy::None; 
    }

    std::string DMARCChecker::org_domain(const std::string& domain) {
        std::string result = domain; // copy over

        size_t dot_count = std::count(result.begin(), result.end(), '.');

        // This isn't entirely PSL compliant, some MLDs may return issues if 
        // they're something like: example.vic.gov.au
        ///TODO: Look into Mozilla PSL directory
        while (true) {
            if (dot_count < 2) {
                break;
            }

            size_t first_dot = result.find('.');
            if (first_dot == std::string::npos) {
                break;
            }

            result = result.substr(first_dot + 1);
        }

        return result;
    }

    bool DMARCChecker::aligned(
        const std::string& domain_a, const std::string& domain_b,
        const std::string& mode 
    ) {
        // Normalise to lowercase in case of mixed or capitalisation
        std::string a = domain_a, b = domain_b;
        std::transform(a.begin(), a.end(), a.begin(), ::tolower);
        std::transform(b.begin(), b.end(), b.begin(), ::tolower);

        if (mode == "s") {
            // strict requires an exact match
            return a == b;
        }

        // relaxed requires the root domain to match
        return org_domain(a) == org_domain(b);
    }

    void DMARCChecker::finish(
        std::shared_ptr<EvalState> state, Result result, Policy policy,
        bool spf_aligned, bool dkim_aligned, std::string explanation
    ) {
        std::cout << "[DMARC] result= " << result_to_string(result)
            << " policy=" << policy_to_string(policy)
            << " from=" << state->from_domain
            << (explanation.empty() ? "" : " reason=" + explanation) << std::endl;

        state->callback({
            result, policy, spf_aligned, dkim_aligned,
            state->from_domain, std::move(explanation)
        });
    }
};
