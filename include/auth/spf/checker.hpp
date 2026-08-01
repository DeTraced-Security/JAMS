#pragma once

#include "dns/resolver.hpp"
#include "dns/types.hpp"

#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace SPF {
    enum class Result {
        Pass, // + Sender is authorised
        Fail, // - sender is not authorised, reject
        SoftFail, // ~ Sender is probably not authorised, warn
        Neutral, // ? policy makes no assertion
        None, // no SPF record
        TempError, // DNS Lookup failed
        PermError // SPF record malformed
    };

    std::string_view result_to_stirng(Result r);

    struct CheckResult  {
        Result result{Result::None};
        std::string what; // Human-readable reason
    };

    using CheckCallback = std::function<void(CheckResult)>;

    // Evaluates the SPF policy for an incoming SMTP message per RFC 7208.
    //
    // Usage:
    //   Checker checker(resolver);
    //   checker.check("sender@example.com", "203.0.113.1",
    //       [](spf::CheckResult r) {
    //           if (r.result == spf::Result::Fail) { /* reject */ }
    //       });
    //
    // Mechanism evaluation order (RFC 7208 5):
    //   all, include, a, mx, ptr (deprecated), ip4, ip6, exists
    //
    // Limitations:
    //   - ptr mechanism is not implemented (deprecated, RFC 7208 5.5)
    //   - exists mechanism is not implemented
    //   - Macro expansion (RFC 7208 7) is not implemented
    //   - Maximum DNS lookup count enforced: 10 (RFC 7208 4.6.4)
    //
    // Threading: single-threaded; all calls from the io_uring event loop thread.
    class Checker {
        public:
            explicit Checker(DNS::Resolver& resolver);

            /// @brief Check the SPF headers 
            /// @param mail_from 
            /// @param client_ip 
            /// @param helo_domain 
            /// @param callback 
            void check(
                const std::string& mail_from, const std::string& client_ip,
                const std::string& helo_domain, CheckCallback callback
            );
        
        private:
            struct EvalState {
                std::string sender_domain;
                std::string client_ip;
                std::string helo_domain;
                CheckCallback callback;

                uint8_t dns_lookups{0}; // Max 10
                uint8_t depth{0}; // include depth - max 10
            };

            struct Mechanism {
                char qualifier{'+'}; // + - ~ ?
                std::string type;
                std::string value;
            };

            struct SPFRecord {
                std::vector<Mechanism> mechanisms;
                std::string redirect;
                std::string exp;
            };

            /// @brief Parse TXT DNS Records from the request
            /// @param txt 
            /// @param out 
            /// @return bool
            static bool parse_record(const std::string& txt, SPFRecord& out);

            /// @brief Parse SPF Mechanisms from the record
            /// @param token 
            /// @param out 
            /// @return 
            static bool parse_mechanism(const std::string& token, Mechanism& out);

            /// @brief Converts the Mechanism Qualifier into a human-readable result
            /// @param q 
            /// @return SPF::Result
            static Result qualifier_to_result(char q);

            /// @brief Matches and Checks if the given IP is from the expected CIDR expansion
            /// @param client_ip 
            /// @param cidr 
            /// @return 
            static bool ipv4_matches(const std::string& client_ip, const std::string& cidr);

            /// @brief Matches and Checks if the given IP is from the expected CIDR expansion
            /// @param client_ip 
            /// @param cidr 
            /// @return 
            static bool ipv6_matches(const std::string& client_ip, const std::string& cidr);

            // Fetch SPF record and eval

            /// @brief Fetch SPF Record and Evaluate with handle_txt_response
            /// @param domain 
            /// @param state 
            void fetch_and_eval(const std::string& domain, std::shared_ptr<EvalState> state);

            /// @brief Verifies if the SPF record and handles Redirects
            /// @param domain 
            /// @param rr 
            /// @param state 
            void handle_txt_response(const std::string& domain, DNS::ResolveResult rr, std::shared_ptr<EvalState> state);
            
            // Eval SPF record against IP
            
            /// @brief Evaluate records in a first-match-first-serve order
            /// @param record 
            /// @param state 
            void evaluate(const SPFRecord& record, std::shared_ptr<EvalState> state);

            /// @brief Evaluates the overall state and handles `include:` chain spoofing
            /// @param idx 
            /// @param record 
            /// @param mechanisms 
            /// @param state 
            void eval_mechanisms_at(
                size_t idx, const SPFRecord& record, 
                std::shared_ptr<std::vector<Mechanism>> mechanisms,
                std::shared_ptr<EvalState> state
            );

            /// @brief Resolve A/AAAA records
            /// @param domain 
            /// @param mech 
            /// @param state 
            /// @param on_match 
            void check_a_record(
                const std::string& domain, const Mechanism& mech,
                std::shared_ptr<EvalState> state, std::function<void(bool)> on_match
            );

            /// @brief Resolve MX records then A records
            /// @param domain 
            /// @param mech 
            /// @param state 
            /// @param on_match 
            void check_mx_record(
                const std::string& domain, const Mechanism& mech,
                std::shared_ptr<EvalState> state, std::function<void(bool)> on_match
            );

            /// @brief Extracts domain name from user@domain variants
            /// @param mail_from 
            /// @return 
            static std::string extract_domain(const std::string& mail_from);

            /// @brief Finds the CIDR prefix length or defaults to a provided length
            /// @param cidr 
            /// @param default_len 
            /// @return 
            static uint8_t prefix_len(const std::string& cidr, uint8_t default_len);

            /// @brief Finalises the processing before handing over to a provided state's callback
            /// @param state 
            /// @param result 
            /// @param explanation 
            void finish(std::shared_ptr<EvalState> state, Result result, std::string explanation = {});

            DNS::Resolver& resolver_;
    };
};
