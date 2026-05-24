#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <sqlite3.h>

namespace Auth {
    
    // SQLite-backed persistent user credential store.
    //
    // Schema:
    //   CREATE TABLE users (
    //       username   TEXT PRIMARY KEY,
    //       hash       TEXT NOT NULL,   -- PBKDF2-HMAC-SHA256, base64
    //       salt       TEXT NOT NULL,   -- 16 random bytes, base64
    //       iterations INTEGER NOT NULL DEFAULT 100000,
    //       active     INTEGER NOT NULL DEFAULT 1,
    //       created_at INTEGER NOT NULL  -- Unix timestamp
    //   );
    //
    // Password hashing:
    //   PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random salt.
    //   OpenSSL's PKCS5_PBKDF2_HMAC() is used — no extra dependencies.
    //   The stored hash is base64(PBKDF2(password, salt, 100000, SHA256, 32)).
    //
    // Usage:
    //   CredentialStore store("/var/lib/jams/users.db");
    //   store.add_user("alice", "s3cr3t");
    //   bool ok = store.verify("alice", "s3cr3t"); // true
    //   bool ok = store.verify("alice", "wrong");   // false
    class CredentialStore {
        public:
            explicit CredentialStore(const std::string& db_path);
            ~CredentialStore();

            CredentialStore(const CredentialStore&) = delete;
            CredentialStore& operator=(const CredentialStore&) = delete;

            /// @brief Add a new user, returns false on error or existing user
            /// @param username 
            /// @param passwd 
            /// @return 
            bool add_user(const std::string& username, const std::string& passwd);

            /// @brief Verify the credentials, returns false on incorrect, unknown, or inactive accounts.
            /// This function works in constant-time
            /// @param username 
            /// @param passwd 
            /// @return 
            bool verify(const std::string& username, const std::string& passwd);

            /// @brief Deactivate a user account (soft-delete to preserve audit trails)
            /// @param username 
            /// @return 
            bool deactivate_user(const std::string& username);

            /// @brief (re)activate a user's account, if deactivated
            /// @param username 
            /// @return 
            bool activate_user(const std::string& username);

            /// @brief Change a user's password
            /// @param username 
            /// @param old_passwd Old password in B64
            /// @param new_passwd New password in B64
            /// @return 
            bool change_password(
                const std::string& username, const std::string& old_passwd,
                const std::string& new_passwd
            );

            /// @brief Verify is a user exists
            /// @param username 
            /// @return 
            bool user_exists(const std::string& username);

        private:
            struct HashedPassword {
                std::string hash; // base64 encoded SHA256
                std::string salt; // base64 encoded hash salt
                int iterations{100000};
            };

            /// @brief Hash the password in PBKDF2 SHA-256
            /// @param password 
            /// @return 
            static HashedPassword hash_password(const std::string& password);

            /// @brief Returns the b64 encoded 32byte PBKDF2 hash
            /// @param passwd 
            /// @param salt 
            /// @param iterations 
            /// @return 
            static std::string pbkdf2(const std::string& passwd, const std::string& salt, int iterations);

            /// @brief Constant-Time comparison to prevent timing attacks
            /// @param a 
            /// @param b 
            /// @return 
            static bool constant_time_eq(const std::string& a, const std::string&b);

            /// @brief Base64 Encoder helper
            /// @param data 
            /// @param len 
            /// @return 
            static std::string base64_encode(const uint8_t* data, size_t len);

            /// @brief Base64 Decoder helper
            /// @param b64 
            /// @return 
            static std::vector<uint8_t> base64_decode(const std::string& b64);

            /// @brief Execute prebuilt SQL Queries
            /// @param query 
            /// @return 
            bool exec(const std::string& query);

            /// @brief Ensure the SQL schema is valid
            void ensure_schema();

            sqlite3* db_{nullptr};
    };
};
