#pragma once

#include "config/toml_parse.hpp"
#include <csignal>

extern volatile sig_atomic_t g_shutdown;

inline TOMLParser load_configs{"./config/server.toml"};
inline const auto configs = load_configs.fetch_configs();

inline std::string get_hostname() {
    std::string result{};
    
    for (auto& host : configs) {
        if (host.first == "hostname") {
            result = host.second;
        }
    }

    return result;
};

inline std::string get_mailroot() {
    std::string result{};
    for (auto& root : configs) {
        if (root.first == "mailroot") {
            result = root.second;
        }
    }

    return result;
}

inline std::string get_db_path() {
    std::string result{};

    for (auto& db : configs) {
        if (db.first == "db_path") {
            result = db.second;
        }
    }

    return result;
}
