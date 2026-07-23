#include "sasl.hpp"
#include "globals.hpp"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <iostream>

namespace Auth {
    SASLSession::SASLSession(CredentialStore& store) : store_(store) {}

    SASLSession::Response SASLSession::begin(
        const std::string& mechanism, const std::string& response
    ) {
        if (authenticated_) {
            return {503, "Already authenticated"};
        }

        if (++attempts_ > MAX_AUTH_ATTEMPTS) {
            return {534, "Too many authentication attempts"};
        }

        // Normalise the mechanism to UPPERcase
        std::string mech = mechanism;
        for (char c : mech) {
            c = static_cast<char>(std::toupper(c));
        }

        if (mech == "PLAIN") {
            mechanism_ = Mechanism::Plain;
            return begin_plain(response);
        }
        if (mech == "LOGIN") {
            mechanism_ = Mechanism::Login;
            return begin_login();
        }

        return {504, "Authentication mechanism not supported"};
    }

    SASLSession::Response SASLSession::respond(const std::string& response) {
        // RFC 4954: "*" means the client wants to cancel the exchange
        if (response == "*") {
            reset();
            return {501, "Authentication cancelled"};
        }

        switch (state_) {
            case State::WaitingPlainResponse: {
                return process_plain(response);
            }
            case State::WaitingLoginUsername: {
                return process_login(response);
            }
            case State::WaitingLoginPassword: {
                return process_login(response);
            }

            default: {
                return {503, "No authentication in progress"};
            }
        }
    }

    void SASLSession::reset() {
        state_ = State::Idle;
        authenticated_ = false;
        username_.clear();
        pending_username_.clear();
        attempts_ = 0;
    }

    SASLSession::Response SASLSession::begin_plain(const std::string& response) {
        if (response.empty()) {
            // No initial response, send challenge and wait
            state_ = State::WaitingPlainResponse;
            return {334, ""}; // RFC 4616 says we send an empty challenge
        }

        // Initial response is provided inline, we can process it immediately
        return process_plain(response);
    }

    SASLSession::Response SASLSession::process_plain(const std::string& b64) {
        state_ = State::Idle;
        std::string decoded = base64_decode(b64);

        if (decoded.empty()) {
            return auth_failure();
        }

        // Split on NUL bytes: [authzid \0] authcid \0 passwd
        size_t first_nul = decoded.find('\0');
        if (first_nul == std::string::npos) {
            return auth_failure();
        }

        size_t second_nul = decoded.find('\0', first_nul + 1);
        if (second_nul == std::string::npos) {
            return auth_failure();
        }

        //authcid os betweem two NULs
        std::string authcid = decoded.substr(first_nul + 1, second_nul - first_nul - 1);
        std::string passwd = decoded.substr(second_nul + 1);

        if (authcid.empty() || passwd.empty()) {
            return auth_failure();
        }

        logger.info("[SASL] PLAIN auth attempt for user: " + authcid);

        if (store_.verify(authcid, passwd)) {
            username_ = authcid;
            return auth_success();
        }

        return auth_failure();
    }

    SASLSession::Response SASLSession::begin_login() {
        state_ = State::WaitingLoginUsername;
        return {334, base64_encode("Username:")};
    }

    SASLSession::Response SASLSession::process_login(const std::string& b64) {
        if (state_ == State::WaitingLoginUsername) {
            pending_username_ = base64_decode(b64);
            if (pending_username_.empty()) {
                return auth_failure();
            }

            state_ = State::WaitingLoginPassword;
            return {334, base64_encode("Password:")};
        }

        if (state_ == State::WaitingLoginPassword) {
            state_ = State::Idle;
            std::string password = base64_decode(b64);

            if (password.empty() || pending_username_.empty()) {
                return auth_failure();
            }

            logger.info("[SASL] LOGIN auth attempt for user: " + pending_username_);

            if (store_.verify(pending_username_, password)) {
                username_ = pending_username_;
                pending_username_.clear();
                return auth_success();
            }

            pending_username_.clear();
            return auth_failure();
        }

        return {503, "No authentication in progress"};
    }

    SASLSession::Response SASLSession::auth_success() {
        authenticated_ = true;
        logger.info("[SASL] Authenticated: " + username_);

        return {235, "2.7.0 Authentication successful"};
    }

    SASLSession::Response SASLSession::auth_failure() {
        authenticated_ = false;
        username_.clear();
        pending_username_.clear();
        state_ = State::Idle;

        logger.error("[SASL] Authentication failed");

        return {535, "5.7.8 Authentication credentials invalid"};
    }

    std::string SASLSession::base64_encode(const std::string& input) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());

        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, mem);
        BIO_write(b64, input.data(), static_cast<int>(input.size()));
        BIO_flush(b64);

        BUF_MEM* buf{};
        BIO_get_mem_ptr(mem, &buf);
        std::string result(buf->data, buf->length);
        BIO_free_all(b64);

        return result;
    }

    std::string SASLSession::base64_decode(const std::string& b64) {
        if (b64.empty()) {
            return {};
        }

        std::vector<char> result(b64.size());

        BIO* b64_bio = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
        BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64_bio, mem);

        int n = BIO_read(b64_bio, result.data(), static_cast<int>(result.size()));
        BIO_free_all(b64_bio);

        if (n <= 0) {
            return {};
        }

        return std::string(result.data(), static_cast<size_t>(n));
    }
};
