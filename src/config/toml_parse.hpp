#pragma once

#include "tomlcpp.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <optional>

class TOMLParser {
    public:
        explicit TOMLParser(const std::string path);
        ~TOMLParser();

        static void error(const char* msg) {
            std::fprintf(stderr, "[TOML] ERROR: %s\n", msg);
            return;
        };

        std::unordered_map<std::string, std::string> fetch_configs();

    private:
        bool load_configs();
        std::string path_;
        std::optional<toml::Result> toml_results;

};
