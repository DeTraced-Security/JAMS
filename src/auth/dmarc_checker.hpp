#pragma once

#include "dns/dns_resolver.hpp"
#include "spf_checker.hpp"
#include "dkim_verifier.hpp"
#include <functional>
#include <string>
#include <vector>

namespace DMARC {
    enum class Policy {
        None, // p=none, monitor only with no action
        Quarantine, // p=quarantine, deliver to spam
        Reject, // p=reject, refuse to deliver
    };

    std::string_view policy_to_string(Policy p);

    enum class Result {
        Pass, // SPF or DKIM passed
        Fail, // SPF or DKIM failed
        PermError, // malformed DMARC
        TempError, // DNS Failure
        None // No record found
    };

    std::string_view result_to_string(Result r);

    struct CheckResult {
        Result result{Result::None};
        Policy policy{Policy::None}; // Effective after pct= sampling
        bool spf_passed{false};
        bool dkim_passed{false};
        std::string from_domain;
        std::string explanation;
    };

    using CheckCallback = std::function<void(CheckResult)>;

    struct DMARCRecord {
        Policy policy{Policy::None}; // p= tag
        Policy subdomain_policy{Policy::None}; // sp= which defaults to p=
        std::string adkim{"r"}; // adkim= "r" relaxed or "s" strict
        std::string aspf{"r"}; // ""
        std::string rua; // rua= aggregate report 
        std::string ruf; // ruf= forensic report
        std::string fo{"0"}; // fo= failure reporting
        std::string rf{"afrf"}; // rf= report format
        uint32_t ri{86400}; // ri= reporting interval
    };

    // Evaluates DMARC policy for an inbound message per RFC 7489.
    //
    // Usage:
    //   checker.check(
    //       from_domain,         // domain from RFC 5322 From: header
    //       mail_from_domain,    // envelope sender domain (for SPF alignment)
    //       spf_result,          // result from SpfChecker
    //       dkim_results,        // results from DkimVerifier (all signatures)
    //       [](dmarc::CheckResult r) {
    //           if (r.result == dmarc::Result::Fail &&
    //               r.policy == dmarc::Policy::Reject)
    //               // reject the message
    //       });
    //
    // Alignment:
    //   SPF alignment: compares envelope sender domain with From: domain
    //   DKIM alignment: compares d= tag with From: domain
    //   Both support strict (exact match) and relaxed (organisational domain match)
    //
    // Organisational domain:
    //   Determined by stripping one subdomain level: mail.example.com -> example.com
    //   Full PSL (Public Suffix List); currently we strip
    //   one level which is correct for the vast majority of domains.
    //
    // pct= tag:
    //   RFC 7489 6.6.4: only apply policy to pct% of messages.
    //   We evaluate this deterministically based on message properties
    //   rather than randomly, for reproducibility.
    //
    // Threading: single-threaded; all calls from the io_uring event loop thread
    class DMARCChecker {
        public:
            explicit DMARCChecker(DNS::DNSResolver& resolver);

            /// @brief Check and validate the DMARC records to maintain integrity with the RFC
            /// @param from_domain 
            /// @param from_from_domain 
            /// @param spf_result 
            /// @param dkim_results 
            /// @param callback 
            void check(
                const std::string& from_domain, const std::string& from_from_domain,
                SPF::Result spf_result, const std::vector<DKIM::VerifyResult>& dkim_results,
                CheckCallback callback
            );
        
        private:

            /// @brief Parse the records and set what we need to continue
            /// @param txt 
            /// @return 
            static std::optional<DMARCRecord> parse_record(const std::string& txt);
            
            /// @brief Parse the policies and set what we need to continue
            /// @param value 
            /// @return 
            static Policy parse_policy(const std::string& value);

            /// @brief Extract the organisation/root domain
            /// @param domain 
            /// @return 
            static std::string org_domain(const std::string& domain);

            /// @brief Check that the two domains align under relaxed or strict modes
            /// @param domain_a 
            /// @param domain_b 
            /// @param mode 
            /// @return 
            static bool aligned(const std::string& domain_a, const std::string& domain_b, const std::string& mode);

            struct EvalState {
                std::string from_domain;
                std::string mail_from_domain;
                SPF::Result spf_result;
                std::vector<DKIM::VerifyResult> dkim_results;
                CheckCallback callback;
            };

            /// @brief Fetch the DMARC record and evaluate with the resolver TXT handler
            /// @param dmarc_domain 
            /// @param from_domain 
            /// @param is_from_subdomain_fallback 
            /// @param state 
            void fetch_and_evaluate(
                const std::string& dmarc_domain, const std::string& from_domain,
                bool is_from_subdomain_fallback, std::shared_ptr<EvalState> state
            );

            /// @brief Evaluates the records to see if they match the DMARC policy
            /// @param record 
            /// @param is_subdomain 
            /// @param state 
            void evaluate(const DMARCRecord& record, bool is_subdomain, std::shared_ptr<EvalState> state);

            /// @brief Finalise the chain by handing over to the state callback
            /// @param state 
            /// @param result 
            /// @param policy 
            /// @param spf_aligned 
            /// @param dkim_aligned 
            /// @param explanation 
            void finish(
                std::shared_ptr<EvalState> state, Result result, Policy policy,
                bool spf_aligned, bool dkim_aligned, std::string explanation = ""
            );

            DNS::DNSResolver& resolver_;
    };
};
