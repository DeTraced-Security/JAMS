#include "dkim_verifier.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>

namespace DKIM {
    std::string_view result_to_string(Result r) {
        switch (r) {
            case Result::Pass: {
                return "pass";
            }
            case Result::Fail: {
                return "fail";
            }
            case Result::PermError: {
                return "permerror";
            }
            case Result::TempError: {
                return "temperror";
            }
            case Result::None: {
                return "none";
            }
        }

        return "unknown";
    }

    DKIMVerifier::DKIMVerifier(DNS::DNSResolver& resolver) : resolver_(resolver) {}

    void DKIMVerifier::verify(const std::string& raw_headers, const std::string& raw_body, VerifyCallback callback) {
        auto dkim_headers = extract_dkim_headers(raw_headers);

        if (dkim_headers.empty()) {
            callback({Result::None, {}, {}, "No DKIM-Signature header found"});
            return;
        }

        // Verify each header independently
        for (const auto& header_value : dkim_headers) {
            auto signature = parse_signature(header_value);

            if (!signature) {
                callback({Result::PermError, {}, {}, "Failed to parse DKIM-Signature"});
                continue;
            }

            auto state = std::make_shared<VerifyState>();
            state->sig = std::move(*signature);
            state->raw_headers = raw_headers;
            state->raw_body = raw_body;
            state->dkim_header_value = header_value;
            state->callback = callback; // We can reuse the callback for all signatures

            fetch_key_and_verify(state);
        }
    }

    std::vector<std::string> DKIMVerifier::extract_dkim_headers(const std::string& raw_headers) {
        std::vector<std::string> result{};
        std::istringstream ss(raw_headers);
        std::string line;
        std::string current_header;
        std::string current_name;

        /// Flush buffers and save last-known headers
        auto flush = [&]() {
            if (current_name == "dkim-signature" && !current_header.empty()) {
                // extract the value after ':'
                auto colon = current_header.find(':');
                if (colon != std::string::npos) {
                    result.push_back(current_header.substr(colon + 1));
                }
            }

            current_header.clear();
            current_name.clear();
        };

        while (std::getline(ss, line)) {
            // Strip trailing CR line ends
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.empty()) {
                flush();
                break; // We've reached the last of the headers
            }

            // Folded headers
            if (line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                current_header += '\n' + line;
                continue;
            }

            flush();

            // New header name extraction
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                current_name = line.substr(0, colon);
                
                std::transform(current_name.begin(), current_name.end(), current_name.begin(), ::tolower);
            }

            current_header = line;
        }

        flush();

        return result;
    }


    std::unordered_map<std::string, std::string> DKIMVerifier::parse_tag_list(
        const std::string& input
    ) {
        // Tag Value parsing as per:
        // tag-list = tag-spec *( ";" tag-spec ) [ ";" ]
        // tag-spec = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]

        std::unordered_map<std::string, std::string> tags;
        std::istringstream ss(input);
        std::string token;

        while (std::getline(ss, token, ';')) {
            // Trim white spaces and folding 
            auto trim = [](std::string s) {
                size_t start = s.find_first_not_of(" \t\r\n");
                size_t end = s.find_last_not_of(" \t\r\n");

                if (start == std::string::npos) {
                    return std::string{};
                }

                return s.substr(start, end - start + 1);
            };

            token = trim(token);
            if (token.empty()) {
                continue;
            }

            auto eq = token.find('=');
            if (eq == std::string::npos) {
                continue;
            }

            std::string name = trim(token.substr(0, eq));
            std::string value = trim(token.substr(eq + 1));

            // Remove internal foldings from value
            std::string clean_value;
            bool prev_ws = false;

            for (char c : value) {
                if (c  == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    prev_ws = true;
                } else {
                    if (prev_ws && !clean_value.empty()) {
                        clean_value += ' '; // normalise to whitespace
                    }

                    clean_value += c;
                    prev_ws = false;
                }
            }

            tags[name] = clean_value;
        }

        return tags;
    }

    std::optional<Signature> DKIMVerifier::parse_signature(const std::string& header_value) {
        auto tags = parse_tag_list(header_value);

        Signature signature;

        // Required tags
        auto get = [&](const std::string& key) -> std::optional<std::string> {
            auto itr = tags.find(key);

            if (itr == tags.end()) {
                return std::nullopt;
            }

            return itr->second;
        };

        auto v = get("v"); 
        if (!v || *v != "1") {
            return std::nullopt;
        }

        auto a = get("a"); 
        if (!a) {
            return std::nullopt;
        }

        auto d = get("d"); 
        if (!d || d->empty()) {
            return std::nullopt;

        }

        auto s = get("s"); 
        if (!s || s->empty()) {
            return std::nullopt;
        }

        auto h = get("h"); 
        if (!h || h->empty()) {
            return std::nullopt;
        }


        auto bh = get("bh"); 
        if (!bh || bh->empty()) {
            return std::nullopt;
        }


        auto b  = get("b");  
        if (!b  || b->empty()) {
            return std::nullopt;
        }

        signature.version = *v;
        signature.algorithm = *a;
        signature.domain = *d;
        signature.selector = *s;
        signature.body_hash = *bh;
        signature.signature = *b;

        // Parse header list
        std::istringstream hss(*h);
        std::string header;
        
        while (std::getline(hss, header, ':')) {
            // trim
            auto start = header.find_first_not_of(" \t");
            auto end = header.find_last_not_of(" \t");

            if (start != std::string::npos) {
                signature.signed_headers.push_back(
                    header.substr(start, end - start + 1)
                );
            }
        }

        // Optional Tags
        if (auto c = get("c")) {
            signature.canonicalization = *c;
        }

        if (auto q = get("q")) {
            signature.query_method = *q;
        }
    
        if (auto t = get("t")) {
            signature.timestamp = std::stoull(*t);
        }
    
        if (auto x = get("x")) {
            signature.expiry = std::stoull(*x);
        }

        if (auto l = get("l")) {
            signature.body_length = std::stoll(*l);
        }

        if (auto i = get("i")) {
            signature.agent_or_userid = *i;
        }

        if (auto z = get("z")) {
            signature.copied_headers   = *z;
        }

        // Parse header and body canonicalisation
        auto slash = signature.canonicalization.find('/');

        if (slash == std::string::npos) {
            signature.header_canon = signature.canonicalization;
            signature.body_canon = "simple"; // This is the default according to RFC 6376 3.4
        } else {
            signature.header_canon = signature.canonicalization.substr(0, slash);
            signature.body_canon = signature.canonicalization.substr(slash + 1);
        }

        // Validate the algorithm name
        if (signature.algorithm != "rsa-sha256" && signature.algorithm != "ed25519-sha256") {
            std::cerr << "[DKIM] unsupported algorithm: " << signature.algorithm << std::endl;
            return std::nullopt;
        }

        return signature;
    }

    std::optional<KeyRecord> DKIMVerifier::parse_key_record(const std::string& txt) {
        auto tags = parse_tag_list(txt);
        KeyRecord key;

        if (auto v = tags.find("v"); v != tags.end()) {
            if (v->second != "DKIM1") {
                std::cerr << "[DKIM] unsupported key version: " << v->second << std::endl;
                return std::nullopt;
            }

            key.version = v->second;
        }

        auto p = tags.find("p");
        if (p == tags.end() || p->second.empty()) {
            // An empty p= key means it was revoked - RFC 6376 3.6.1
            // in rare circumstances it might be empty on receival
            std::cerr << "[DKIM] key revoked or empty" << std::endl;
            return std::nullopt;
        }

        key.pk_b64 = p->second;

        // Set the algo, types, and flags
        if (auto k = tags.find("k"); k != tags.end()) {
            key.key_type = k->second;
        }

        if (auto h = tags.find("h"); h != tags.end()) {
            key.hash_algos = h->second;
        }

        if (auto s = tags.find("s"); s != tags.end()) {
            key.service_type = s->second;
        }

        if (auto t = tags.find("t"); t != tags.end()) {
            key.flags = t->second;
        }

        // validate the key type
        if (key.key_type != "rsa" && key.key_type != "ed25519") {
            std::cerr << "[DKIM] unsupported key type: " << key.key_type << std::endl;
            return std::nullopt;
        }

        return key;
    }    

    std::string DKIMVerifier::canonicalize_body(const std::string& body, const std::string& method) {
        if (method == "relaxed") {
            // Relaxed body reduces WSP, removes trailing WSP, ignores empty lines
            // and ensures the body ends with CRLF

            std::string result;
            std::istringstream ss(body);
            std::string line;
            std::string pending; // Buffer trailing emptiness

            while (std::getline(ss, line)) {
                if (!line.empty()) {
                    line.pop_back();
                }

                // Reduce the wsp to a single SP
                std::string canonical;
                bool in_ws = false;
                for (char c : line) {
                    if (c == ' ' || c == '\t') {
                        in_ws = true; // this shall remain true, for single SP
                    } else {
                        if (in_ws) {
                            canonical += ' ';
                            in_ws = false;
                        }

                        canonical += c;
                    }
                }

                // Remove trailing SP
                if (canonical.empty()) {
                    pending += '\r\n'; 
                } else {
                    result += pending;
                    pending.clear();
                    result += canonical + "\r\n";
                }
            }

            // If the body is empty, treat it as a single CRLF
            if (result.empty()) {
                return "\r\n";
            }

            return result;
        } else {
            // simple - reduce and ignore

            std::string normalised;
            for (size_t i = 0; i < body.size(); i++) {
                if (body[i] == '\n') {
                    if (normalised.empty() || normalised.back() != '\r') {
                        normalised += '\r';
                    }

                    normalised += '\n';
                } else {
                    normalised += body[i];
                }
            }

            while (
                normalised.size() >= 2 && 
                normalised.substr(normalised.size() - 2) == "\r\n"
            ) {
                normalised.resize(normalised.size() - 2);
            }

            normalised += "\r\n";

            if (normalised == "\r\n") {
                return "\r\n";
            }

            return normalised;
        }
    }

    std::string DKIMVerifier::canonicalize_header(
        const std::string& name, const std::string& value,
        const std::string& method
    ) {
        if (method == "relaxed") {
            // lowercase, unfold, reduce, and remove trailing WSP

            std::string canon_name = name;
            std::transform(canon_name.begin(), canon_name.end(), canon_name.begin(), ::tolower);

            // unfold and compress WSP
            std::string canon_value;
            bool in_ws{false};
            bool skip_ws{false}; 

            for (size_t i = 0; i < value.size(); ++i) {
                char c = value[i];

                if (c == '\r' && i + 1 < value.size() && value[i + 1] == '\n') {
                    ++i;
                    skip_ws = true;
                    in_ws = true;
                    continue;
                }

                if (skip_ws && (c == ' ' || c == '\t')) {
                    in_ws = true;
                    skip_ws = false;
                    continue;
                }

                skip_ws = false;

                if (c == ' ' || c == '\t') {
                    in_ws = true;
                } else {
                    if (in_ws && !canon_value.empty()) {
                        canon_value += ' ';
                    }

                    in_ws = false;
                    canon_value += c;
                }
            }

            // Trim tailing SP
            while (!canon_value.empty() && canon_value.back() == ' ') {
                canon_value.pop_back();
            }

            // trim leading SP
            if (size_t start = canon_value.find_first_not_of(' ') != std::string::npos) {
                canon_value = canon_value.substr(start);
            }

            return canon_name + ":" + canon_value + "\r\n";
        } else {
            // Simple - header is used as is
            std::string result = name + ":" + value;

            if (result.size() < 2 || result.substr(result.size() - 2) != "\r\n") {
                result += "\r\n";
            }

            return result;
        }
    }

    std::string DKIMVerifier::build_signed_header_block(
        const std::vector<std::string>& all_raw_headers,
        const Signature& signature, const std::string& dkim_value
    ) {
        // Build a map of name to list of values and process bottom-up

        std::unordered_map<std::string, std::vector<std::string>> header_map;

        for (const auto& raw : all_raw_headers) {
            auto colon = raw.find(':');

            if (colon == std::string::npos) {
                continue;
            }

            std::string name = raw.substr(0, colon);
            std::string value = raw.substr(colon + 1);

            std::transform(name.begin(), name.end(), name.begin(), ::tolower);

            header_map[name].push_back(value);
        }

        // track consumption of multiple occuring headers
        std::unordered_map<std::string, size_t> consumed;
        std::string result;

        for (const auto& header : signature.signed_headers) {
            std::string lower_name = header;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

            auto itr = header_map.find(lower_name);
            if (itr == header_map.end() || itr->second.empty()) {
                continue; // treat as a missing header
            }

            // consume bottom-up
            size_t& idx = consumed[lower_name];
            size_t pos = itr->second.size() - 1 - idx;

            if (idx >= itr->second.size()) {
                continue;
            }

            ++idx;

            result += canonicalize_header(lower_name, itr->second[pos], signature.header_canon);
        }

        // Append the signature to b=
        std::string dkim_for_signing = dkim_value;
        auto b_pos = dkim_for_signing.find("b=");

        if (b_pos != std::string::npos) {
            size_t end = dkim_for_signing.find(";", b_pos + 2);

            if (end == std::string::npos) {
                dkim_for_signing = dkim_for_signing.substr(0, b_pos + 2);
            } else {
                dkim_for_signing = dkim_for_signing.substr(0, b_pos + 2) + dkim_for_signing.substr(end);
            }
        }

        result += canonicalize_header("dkim-signature", dkim_for_signing, signature.header_canon);

        return result;
    }

    std::vector<uint8_t> DKIMVerifier::sha256(const std::string& data) {
        std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
        SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());

        return hash;
    }

    std::string DKIMVerifier::base64_encode(const std::vector<uint8_t>& data) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, mem);
        BIO_write(b64, data.data(), static_cast<int>(data.size()));
        BIO_flush(b64);

        BUF_MEM* buff{};
        BIO_get_mem_ptr(mem, &buff);
        std::string result(buff->data, buff->length);
        BIO_free_all(b64);

        return result;
    }

    std::vector<uint8_t> DKIMVerifier::base64_decode(const std::string& b64) {
        // Strip white spaces
        std::string clean;
        clean.reserve(b64.size());

        for (char c : b64) {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                clean += c;
            }
        }

        std::vector<uint8_t> result(clean.size());
        BIO* b64_bio = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(clean.data(), static_cast<int>(clean.size()));

        BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64_bio, mem);

        int n = BIO_read(b64_bio, result.data(), static_cast<int>(result.size()));

        BIO_free_all(b64_bio);

        if (n < 0) {
            return {};
        }

        result.resize(static_cast<size_t>(n));
        return result;
    }

    bool DKIMVerifier::verify_rsa_sha256(
        const std::vector<uint8_t>& message_hash,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& pub_key_der
    ) {
        // TODO
    }

    bool DKIMVerifier::verify_ed25519(
        const std::vector<uint8_t>& signed_data,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key
    ) {
        // TODO
    }

    void DKIMVerifier::fetch_key_and_verify(std::shared_ptr<VerifyState> state) {
        // TODO
    }

    void DKIMVerifier::do_verify(const std::shared_ptr<VerifyState> state, const KeyRecord& key) {
        // TODO

    }

    void DKIMVerifier::finish(
        std::shared_ptr<VerifyState> state, Result result,
        std::string explanation
    ) {
        // TODO
    }
};
