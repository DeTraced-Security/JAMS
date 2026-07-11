#pragma once

#include "config/toml_parse.hpp"
#include <csignal>

extern volatile sig_atomic_t g_shutdown;

const TOMLParser load_configs = TOMLParser("./config/server.toml");
extern const auto configs = TOMLParser::fetch_configs();

std::string get_hostname() {
    for (auto& host : configs) {
        if (host.first == "hostname") {
            return host.second;
        }
    }
};

std::string get_mailroot() {
    for (auto& root : configs) {
        if (root.first == "mailroot") {
            return root.second;
        }
    }
}

std::string get_db_path() {
    for (auto& db : configs) {
        if (db.first == "db_path") {
            return db.second;
        }
    }
}
