#pragma once

#include "dns/resolver.hpp"
#include "dns/types.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <openssl/evp.h>

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
    class Verifier {
        public:
            /// @param resolver 
            explicit Verifier(DNS::Resolver& resolver);


            /// @brief Verify DKIM signatures
            /// @param raw_headers 
            /// @param raw_body 
            /// @param callback 
            void verify(const std::string& raw_headers, const std::string& raw_body, VerifyCallback callback);

        private:
            /// @brief Extract DKIM headers from the raw header data
            /// @param raw_headers 
            /// @return 
            static std::vector<std::string> extract_dkim_headers(const std::string& raw_headers);

            /// @brief Parse applicable DKIM headers from the extracted values
            /// @param header_value 
            /// @return 
            static std::optional<Signature> parse_signature(const std::string& header_value);

            /// @brief Parse applicable key records into a record cache
            /// @param txt 
            /// @return 
            static std::optional<KeyRecord> parse_key_record(const std::string& txt);

            /// @brief Parse tag=value lists shared by header and signature parsing
            /// @param input 
            /// @return 
            static std::unordered_map<std::string, std::string> parse_tag_list(const std::string& input);

            /// @brief Canonicalise the message body as per RFC 6376 3.4
            /// @param body 
            /// @param method 
            /// @return 
            static std::string canonicalize_body(const std::string& body, const std::string& method);

            /// @brief Canonicalise a single header as per RFC 6376 3.4
            /// @param name 
            /// @param value 
            /// @param method 
            /// @return 
            static std::string canonicalize_header(
                const std::string& name, const std::string& value, 
                const std::string& method
            );

            /// @brief Build canonicalised header block for signing
            /// @param all_headers 
            /// @param sig 
            /// @param dkim_header_value 
            /// @return 
            static std::string build_signed_header_block(
                const std::vector<std::string>& all_headers, const Signature& sig,
                const std::string& dkim_header_value
            );

            /// @brief Compute SHA-256 hash of the data and return raw bytes
            /// @param data 
            /// @return 
            static std::vector<uint8_t> sha256(const std::string& data);

            /// @brief Encode into Base64
            /// @param data 
            /// @return 
            static std::string base64_encode(const std::vector<uint8_t>& data);

            /// @brief Decode from Base64
            /// @param base64 
            /// @return 
            static std::vector<uint8_t> base64_decode(const std::string& base64);

            static bool verify_ed25519(
                const std::vector<uint8_t>& signed_data, const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key
            );

            static bool verify_rsa_sha256(
                const std::vector<uint8_t>& message_hash, const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& pub_key_der
            );

            /// @brief Verifiable Session States
            struct VerifyState {
                Signature sig;
                std::string raw_headers;
                std::string raw_body;
                std::string dkim_header_value; // original header for signing
                VerifyCallback callback;
            };

            /// @brief Verify the integrity of the DKIM public key
            /// @param state 
            void fetch_key_and_verify(std::shared_ptr<VerifyState> state);

            /// @brief Key Verification, per session state
            /// @param state 
            /// @param key 
            void do_verify(std::shared_ptr<VerifyState> state, const KeyRecord& key);

            /// @brief Finalise the chain by handing over to the state callback
            /// @param state 
            /// @param result 
            /// @param explanation 
            void finish(std::shared_ptr<VerifyState> state, Result result, std::string explanation = {});

            DNS::Resolver& resolver_;

            /// @brief DKIM Key cache
            std::unordered_map<std::string, KeyRecord> key_cache_;
    };
};
