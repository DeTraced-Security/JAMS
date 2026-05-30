#include "cred_store.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <vector>

namespace Auth {
    CredentialStore::CredentialStore(const std::string& db_path) {
        int db = sqlite3_open(db_path.c_str(), &db_);

        if (db != SQLITE_OK) {
            std::string err = sqlite3_errmsg(db_);
            sqlite3_close_v2(db_);
            db_ = nullptr;

            throw std::runtime_error("[CredStore] Failed to open DB: " + err);
        }

        exec("PRAGMA journal_mode=WAL");
        exec("PRAGMA foreign_keys=ON");
        ensure_schema();

        std::cout << "[Auth] credential store opened: " << db_path << std::endl;
    }

    CredentialStore::~CredentialStore() {
        if (db_) {
            sqlite3_close_v2(db_);
        }
    }

    void CredentialStore::ensure_schema() {
        exec(R"sql(
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                iterations INTEGER NOT NULL DEFAULT 100000,
                active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );
        )sql");
    }

    bool CredentialStore::add_user(const std::string& username, const std::string& passwd) {
        if (username.empty() || passwd.empty()) {
            return false;
        }

        if (user_exists(username)) {
            return false;
        }

        auto hashed = hash_password(passwd);
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        // SQLite Statement
        sqlite3_stmt* stmt = nullptr;
        const char* sql = 
            "INSERT INTO users (username, hash, salt, iterations, active, created_at) "
            "VALUES (?, ?, ?, ?, 1, ?)";
        
        // Prepare the statement
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        // Bind the values to avoid SQL Injection via concatenation
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashed.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, hashed.salt.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 4, hashed.iterations);
        sqlite3_bind_int64(stmt, 5, static_cast<sqlite3_int64>(now));

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt); // Construct the statement with the binds

        if (ok) {
            std::cout << "[auth] user added: " << username << std::endl;
        } else {
            std::cerr << "[auth] add_user failed: " << sqlite3_errmsg(db_) << std::endl;
        }

        return ok;
    }

    bool CredentialStore::verify(const std::string& username, const std::string& passwd) {
        if (username.empty() || passwd.empty()) {
            return false;
        }

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT hash, salt, iterations, FROM users "
            "WHERE username = ? AND active = 1";
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        bool user_found = false;
        std::string stored_hash, salt;
        int iterations = 100000;

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user_found = user_exists(username);

            const char* hash_cstr = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 0)
            );
            const char* salt_cstr = reinterpret_cast<const char*>(
                sqlite3_column_text(stmt, 1)
            );

            // Safe-guard against potential NULL values that may crash the call
            if (!hash_cstr || !salt_cstr) {
                sqlite3_finalize(stmt);
                return false;
            }
            stored_hash = hash_cstr;
            salt = salt_cstr;
            iterations = sqlite3_column_int(stmt, 2);
        }

        sqlite3_finalize(stmt);

        // Constant-Time evaluation - timing attack prevention
        std::string computed = pbkdf2(
            passwd, salt.empty() ? "deadbeef" : salt,
            iterations
        );

        if (!user_found) {
            return false;
        }

        return constant_time_eq(computed, stored_hash);
    }

    bool CredentialStore::deactivate_user(const std::string& username) {
        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_prepare_v2(
            db_, "UPDATE users SET active = 0 WHERE username = ?",
            -1, &stmt, nullptr
        ) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);

        return ok;
    }

    bool CredentialStore::activate_user(const std::string& username) {
        sqlite3_stmt* stmt{nullptr};

        if (sqlite3_prepare_v2(
            db_, "UPDATE users SET active = 1 WHERE username = ?",
             -1, &stmt, nullptr
        ) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);

        return ok;
    }

    bool CredentialStore::change_password(
        const std::string& username, const std::string& old_passwd, 
        const std::string& new_passwd
    ) {
        if (old_passwd.empty() || new_passwd.empty() || username.empty()) {
            return false;
        }
        auto hashed_old = hash_password(old_passwd);
        auto hashed_new = hash_password(new_passwd);

        sqlite3_stmt* stmt{nullptr};

        if (sqlite3_prepare_v2(
            db_, "UPDATE users SET hash = ?, salt = ?, iterations = ? "
            "WHERE username = ? AND hash = ?", -1, &stmt, nullptr
        ) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, hashed_new.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hashed_new.salt.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, hashed_new.iterations);
        sqlite3_bind_text(stmt, 4, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, hashed_old.hash.c_str(), -1, SQLITE_STATIC);

        bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);

        return ok;
    }

bool CredentialStore::user_exists(const std::string& username) {
    sqlite3_stmt* stmt{nullptr};

    if (sqlite3_prepare_v2(
        db_, "SELECT 1 FROM users WHERE username = ?",
        -1, &stmt, nullptr
    ) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return ok;
}

    CredentialStore::HashedPassword CredentialStore::hash_password(
        const std::string& passwd
    ) {
        // Generate 16 random bytes for the salt
        uint8_t salt_bytes[16];
        if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
            throw std::runtime_error("[auth/CredStore] RAND_bytes failed");
        }

        HashedPassword hashed;
        hashed.salt = base64_encode(salt_bytes, sizeof(salt_bytes));
        hashed.iterations = 100000;
        hashed.hash = pbkdf2(passwd, hashed.salt, hashed.iterations);

        return hashed;
    }

    std::string CredentialStore::pbkdf2(
        const std::string& passwd, const std::string& salt_b64, 
        int iterations
    ) {
        auto salt = base64_decode(salt_b64);
        uint8_t out[32]; // SHA-256 output in 32 bytes

        int rc = PKCS5_PBKDF2_HMAC(
            passwd.c_str(), static_cast<int>(passwd.size()),
            salt.data(), static_cast<int>(salt.size()),
            iterations, EVP_sha256(), sizeof(out), out
        );

        if (rc != 1) {
            throw std::runtime_error("[auth/CredStore] PBKDF2 failed");
        }

        return base64_encode(out, sizeof(out));
    }

    bool CredentialStore::constant_time_eq(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) {
            // Dummy comparison to avoid length-based timing attacks
            volatile uint8_t diff = 0;
            for (size_t i = 0; i < a.size(); ++i) {
                diff |= static_cast<uint8_t>(a[i]);
            }

            return false;
        }

        // CRYPTO_memcmp is OSSL's constant time comparison
        return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    std::string CredentialStore::base64_encode(const uint8_t* data, size_t len) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new(BIO_s_mem());
        
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_push(b64, mem);
        BIO_write(b64, data, static_cast<int>(len));
        BIO_flush(b64);
        
        BUF_MEM* buf{};
        BIO_get_mem_ptr(mem, &buf);

        std::string result(buf->data, buf->length);
        BIO_free_all(b64);

        return result;
    }

    std::vector<uint8_t> CredentialStore::base64_decode(const std::string& b64) {
        std::vector<uint8_t> result(b64.size());
        BIO* b64_bio = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(b64.data(), static_cast<int>(b64.size()));
        
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

    bool CredentialStore::exec(const std::string& sql) {
        char* err{nullptr};
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);

        if (rc != SQLITE_OK) {
            std::cerr << "[auth] SQL error: " << (err ? err : "unknown") << std::endl;
            sqlite3_free(err);

            return false;
        }

        return true;
    }
};
