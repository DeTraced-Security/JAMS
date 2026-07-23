#include "aliases.hpp"
#include <ctime>
#include "globals.hpp"

std::string extract_domain(const std::string& address) {
    auto pos = address.rfind('@');
    if (pos == std::string::npos) {
        return "";
    }

    std::string domain = address.substr(pos + 1);
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

    return domain;
}

std::string Aliases::resolve(const std::string& address) {
    static constexpr const char* SQL = "SELECT username FROM aliases WHERE alias = ? AND active = 1;";

    sqlite3_stmt* stmt{nullptr};
    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Resolve prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return address;
    }

    sqlite3_bind_text(stmt, 1, address.c_str(), -1, SQLITE_TRANSIENT);
    std::string result = address;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool Aliases::add(
    const std::string& alias, const std::string& username, const AliasPolicy& policy = {}
) {
    static constexpr const char* SQL = "INSERT INTO aliases (alias, username, active, created_at) "
        "VALUES (?, ?, 1, ?);";
    
    sqlite3_stmt* stmt{nullptr};

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Add prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(std::time(nullptr)));

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
        logger.error("[ALIAS] Add insert failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_finalize(stmt);
    return ok;
}

bool Aliases::remove(const std::string& alias) {
    static constexpr const char* SQL = "DELETE FROM aliases WHERE alias = ?;";
    sqlite3_stmt* stmt{nullptr};

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] Remove prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
        logger.error("[ALIAS] Remove delete failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_finalize(stmt);
    return ok;
}

std::vector<std::string> Aliases::list_for(const std::string& username) {
    static constexpr const char* SQL = "SELECT alias FROM aliases WHERE username = ? AND active = 1;";
    sqlite3_stmt* stmt{nullptr};
    std::vector<std::string> out;

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] List For prepare failed: " + std::string(sqlite3_errmsg(db_)));
        return out;
    }

    sqlite3_bind_text(stmt,1, username.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    return out;
}

bool Aliases::is_domain_allowed(const std::string& alias, const std::string& sender_domain) {
    static constexpr const char* SQL = "SELECT COUNT(*) FROM alias_allowed_domains WHERE alias = ?;";
    sqlite3_stmt* stmt{nullptr};

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] is_domain_allowed failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);

    int total = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (total == 0) {
        return true; // no allowlist configured, accept from anyone
    }

    static constexpr const char* CHECK = 
        "SELECT 1 FROM alias_allowed_domains WHERE alias = ? AND domain = ?;";
    sqlite3_stmt* c{nullptr};

    if (sqlite3_prepare_v2(db_, CHECK, -1, &c, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] is_domain_allowed failed: " + std::string(sqlite3_errmsg(db_)));
        return false;
    }

    sqlite3_bind_text(c, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(c, 2, sender_domain.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(c) == SQLITE_ROW;

    sqlite3_finalize(c);
    return ok;
}

void Aliases::schedule_purge(const std::string& alias, const std::string& username, const std::string& maildir_path) {
    static constexpr const char* SQL = "SELECT auto_delete_after FROM aliases WHERE alias = ?;";
    sqlite3_stmt* stmt{nullptr};

    if (sqlite3_prepare_v2(db_, SQL, -1, &stmt, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] schedule_purge failed to prepare: " + std::string(sqlite3_errmsg(db_)));
        return;
    }

    sqlite3_bind_text(stmt, 1, alias.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW || sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
        sqlite3_finalize(stmt);
        return; // no TTL configured
    }

    int ttl = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    int64_t purge_at = static_cast<int64_t>(std::time(nullptr)) + ttl;
    static constexpr const char* INS = 
        "INSERT INTO message_purge_queue (alias, username, maildir_path, purge_at) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt* ins{nullptr};

    if (sqlite3_prepare_v2(db_, INS, -1, &ins, nullptr) != SQLITE_OK) {
        logger.error("[ALIAS] schedule_purge insert failed to prepare: " + std::string(sqlite3_errmsg(db_)));
        return;
    }
    
    sqlite3_bind_text(ins, 1, alias.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 3, maildir_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 4, purge_at);

    sqlite3_step(ins);
    sqlite3_finalize(ins);
}
