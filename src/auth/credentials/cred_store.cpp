#include "cred_store.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <vector>
#include "globals.hpp"

namespace Auth {
    CredentialStore::CredentialStore(const std::string& db_path) {
        int db = sqlite3_open(db_path.c_str(), &db_);

        if (db != SQLITE_OK) {
            std::string err = sqlite3_errmsg(db_);
            sqlite3_close_v2(db_);
            db_ = nullptr;

            logger.error("[FATAL] [CREDSTORE] Failed to open DB: " + err);
            throw std::runtime_error("[CredStore] Failed to open DB: " + err);
        }

        exec("PRAGMA journal_mode=WAL");
        exec("PRAGMA foreign_keys=ON");
        ensure_schema();

        logger.info("[AUTH] Credential Store opened: " + db_path);
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

            CREATE TABLE IF NOT EXISTS aliases (
                alias TEXT PRIMARY KEY, -- full address
                username TEXT NOT NULL, -- target account
                active INTEGER NOT NULL DEFAULT 1,
                max_uses INTEGER,
                uses_count INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alias_allowed_domains (
                alias TEXT NOT NULL,
                domain TEXT NOT NULL,
                PRIMARY KEY (alias, domain),
                FOREIGN KEY (alias) REFERENCES aliases(alias) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS message_purge_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL,
                username TEXT NOT NULL,
                maildir_path TEXT NOT NULL,
                purge_at INTEGER NOT NULL,
                FOREIGN KEY (alias) REFERENCES aliases(alias) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_purge_queue_time ON message_purge_queue(purge_at);
            CREATE INDEX IF NOT EXISTS idx_aliases_username ON aliases(username);
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
            logger.info("[AUTH] User added: " + username);
        } else {
            logger.error("[AUTH] add_user failed: " + std::string(sqlite3_errmsg(db_)));
        }

        return ok;
    }

    bool CredentialStore::verify(const std::string& username, const std::string& passwd) {
        if (username.empty() || passwd.empty()) {
            return false;
        }

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT hash, salt, iterations FROM users "
            "WHERE username = ? AND active = 1";
        
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            logger.error("[auth] SQL Account Verification perpare failed: " + std::string(sqlite3_errmsg(db_)));
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
        
        sqlite3_stmt* sel{nullptr};
        if (sqlite3_prepare_v2(db_, "SELECT hash, salt, iterations FROM users WHERE username = ?", -1, &sel, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(sel, 1, username.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(sel) != SQLITE_ROW) {
            sqlite3_finalize(sel);
            return false;
        }

        std::string stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(sel, 0));
        std::string stored_salt = reinterpret_cast<const char*>(sqlite3_column_text(sel, 1));
        int stored_iterations = sqlite3_column_int(sel, 2);

        sqlite3_finalize(sel);

        auto check = hash_password(old_passwd, stored_salt, stored_iterations);
        if (!constant_time_eq(check.hash, stored_hash)) {
            return false;
        }

        auto hashed_new = hash_password(new_passwd);
        sqlite3_stmt* upd{nullptr};

        if (sqlite3_prepare_v2(db_, "UPDATE users SET hash = ?, salt = ?, iterations = ? WHERE username = ?", -1, &upd, nullptr) != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(upd, 1, hashed_new.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(upd, 2, hashed_new.salt.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(upd, 3, hashed_new.iterations);
        sqlite3_bind_text(upd, 4, username.c_str(), -1, SQLITE_STATIC);

        bool ok = (sqlite3_step(upd) == SQLITE_DONE);
        sqlite3_finalize(upd);

        return ok && sqlite3_changes(db_) > 0;
    }

    CredentialStore::HashedPassword CredentialStore::hash_password(const std::string& password, const std::string& salt, int iterations) {
        HashedPassword hashed;
        hashed.salt = salt;
        hashed.iterations = iterations;
        hashed.hash = pbkdf2(password, hashed.salt, hashed.iterations);

        return hashed;
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
            logger.error("[FATAL] [AUTH] RAND_bytes failed");
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
            logger.error("[FATAL] [AUTH] PBKDF2 faiiled");
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
            logger.error("[AUTH] SQL Error: " + std::string((err ? err : "unknown")));
            sqlite3_free(err);

            return false;
        }

        return true;
    }
};
