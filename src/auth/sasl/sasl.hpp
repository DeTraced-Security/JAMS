#pragma once

#include "auth/credentials/cred_store.hpp"
#include <functional>
#include <optional>
#include <string>

namespace Auth {
    // SASL Mechanisms
    enum class Mechanism {
        Plain,
        Login
    };

    // Handles SMTP AUTH negotiation for PLAIN and LOGIN mechanisms.
    //
    // PLAIN (RFC 4616):
    //   Client sends: AUTH PLAIN [base64(\0username\0password)]
    //   If no initial response, server sends "334 " and client responds.
    //   Single round-trip after initial challenge.
    //
    // LOGIN (RFC 4954 / draft):
    //   C: AUTH LOGIN
    //   S: 334 VXNlcm5hbWU6  ("Username:")
    //   C: <base64(username)>
    //   S: 334 UGFzc3dvcmQ6  ("Password:")
    //   C: <base64(password)>
    //   Two round-trips.
    //
    // Usage:
    //   SaslSession sasl(store);
    //
    //   // Client sends: AUTH PLAIN
    //   auto [code, msg] = sasl.begin("PLAIN", "");
    //   // code=334, msg="" — send challenge
    //
    //   // Client responds with credentials
    //   auto [code2, msg2] = sasl.respond(base64_creds);
    //   // code2=235, msg2="Authentication successful" — or 535 on failure
    //
    //   if (sasl.authenticated()) {
    //       auto user = sasl.username(); // the authenticated username
    //   }
    class SASLSession {
        public:
            explicit SASLSession(CredentialStore& store);

            struct Response {
                int code; // SMTP Response Code
                std::string message; // Response text
            };

            /// @brief Begin the AUTH exchange
            /// @param mechanism PLAIN or LOGIN
            /// @param response B64 data after AUTH PLAIN <data> (can be empty)
            /// @return SMTP response to client
            Response begin(const std::string& mechanism, const std::string& response);

            /// @brief Continue the AUTH exchange with response to a challenge
            /// @param response 
            /// @return The next SMTP response
            Response respond(const std::string& response);

            /// @brief Returns true after a successful auth request
            /// @return 
            bool authenticated() const {
                return authenticated_;
            }

            /// @brief Returns the authenticatd username, if validated by `authenticated`
            /// @return 
            const std::string& username() const {
                return username_;
            }

            /// @brief Returns true if the AUTH exchange is in progress
            /// @return 
            bool in_progress() const {
                return state_ != State::Idle;
            }

            /// @brief Reset the state on RSET or new connection
            void reset();

        private:
            /// @brief Begin the AUTH PLAIN exchange chain
            /// @param response 
            /// @return 
            Response begin_plain(const std::string& response);

            /// @brief Process the data sent during the AUTH PLAIN exchange
            /// @param b64 
            /// @return 
            Response process_plain(const std::string& b64);

            /// @brief Begin the AUTH LOGIN exchange chain
            /// LOGIN is a two-step challenge/response:
            ///   S: 334 VXNlcm5hbWU6  (base64("Username:"))
            ///   C: <base64(username)>
            ///   S: 334 UGFzc3dvcmQ6  (base64("Password:"))
            ///   C: <base64(password)>
            /// @return 
            Response begin_login();

            /// @brief Process the data sent during the AUTH LOGIN exchange
            /// @param b64 
            /// @return 
            Response process_login(const std::string& b64);


            static std::string base64_encode(const std::string& input);
            static std::string base64_decode(const std::string& b64);

            Response auth_success();
            Response auth_failure();

            enum class State {
                Idle,
                WaitingPlainResponse, // Sent 334, waiting for PLAIN creds
                WaitingLoginUsername, // sent 334 Username:, waiting for username
                WaitingLoginPassword, // sent 334 Password:, waiting for password
            };

            CredentialStore& store_;
            State state_{State::Idle};
            Mechanism mechanism_{Mechanism::Plain};
            bool authenticated_{false};
            std::string username_;
            std::string pending_username_; // For LOGIN, holds the username between steps

            static constexpr int MAX_AUTH_ATTEMPTS = 3;
            int attempts_{0};
    };
};
