#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <openssl/evp.h>
#include "dns/dns_resolver.hpp"
#include "dns/dns_types.hpp"

namespace DKIM {
    enum class Result {
        Pass, // Signature is verified
        Fail, // Signature is invalid
        PermError, // malformed signature/key
        TempError, // DNS Failure
        None, // No DKIM header
    };

    std::string_view result_to_string(Result r);

    struct VerifyResult
    {
        Result result{Result::None};
        std::string domain; // d= signing domain
        std::string selector; // s=
        std::string explanation;
    };

    using VerifyCallback = std::function<void(VerifyResult)>;

    // Parsed DKIM Signature tags (RFC 6376 3.5)
    struct Signature {
        // Required Tags
        std::string version; // v= must be 1, anything else is invalid
        std::string algorithm; // a=, this is either rsa-sha256 or ed....-sha256
        std::string domain; // d= signing domain
        std::string selector; // s= key selector
        std::vector<std::string> signed_headers; // h=, CSV header list
        std::string body_hash; // bh=, b64 body hash
        std::string signature; // b=, b64 signature

        // Optional Tags
        std::string canonicalization{"simple/simple"}; // c= header/body
        std::string query_method{"dns/txt"}; // q=
        uint64_t timestamp{0}; // t=
        uint64_t expiry{0}; // x=
        int64_t body_length{-1}; // l=, -1 = entire body
        std::string agent_or_userid; // i=
        std::string copied_headers; // z=

        // Derived Tags
        std::string header_canon; // relaxed or simple
        std::string body_canon; // ""
    };    

    // DKIM storage and lookup DSO
    struct KeyRecord {
        std::string version{"DKIM1"};
        std::string key_type{"rsa"};
        std::string pk_b64; // public key base64
        std::string hash_algos; // h= allowed hash algos
        std::string service_type{"*"}; // s= "*" or "email"
        std::string flags; // t= "y" (testing/yesting) or "s" (strict)
    };

    // Verifies DKIM signatures on inbound messages per RFC 6376.
    //
    // Usage:
    //   verifier.verify(raw_headers, raw_body,
    //       [](dkim::VerifyResult r) {
    //           if (r.result == dkim::Result::Pass) { /* accept */ }
    //       });
    //
    // Multiple DKIM-Signature headers:
    //   All are attempted. The callback is invoked once per signature.
    //   Callers should accept if any Pass result is received.
    //
    // Canonicalization:
    //   Both "relaxed" and "simple" are supported for both header and body,
    //   selected by the c= tag in the DKIM-Signature header.
    //
    // Algorithms:
    //   rsa-sha256    — RSA PKCS#1 v1.5 with SHA-256 (RFC 6376)
    //   ed25519-sha256 — Ed25519 with SHA-256 (RFC 8463)
    //
    // Key caching:
    //   Public keys are cached for the session (by selector._domainkey.domain)
    //   to avoid redundant DNS lookups when multiple signatures share a key.
    //
    // Threading: single-threaded; all calls from the io_uring event loop thread.
    class DKIMVerifier {
        public:
            /// @param resolver 
            explicit DKIMVerifier(DNS::DNSResolver& resolver);


            /// @brief Verify DKIM signatures
            /// @param raw_headers 
            /// @param raw_body 
            /// @param callback 
            void verify(const std::string& raw_headers, const std::string& raw_body, VerifyCallback callback);

        private:

    };
};
