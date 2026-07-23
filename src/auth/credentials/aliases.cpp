#include "aliases.hpp"
#include <ctime>
#include "globals.hpp"

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
    const std::string& alias, const std::string& username, uint64_t expiry = 0,
    const std::string& receives_from = "*"
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
