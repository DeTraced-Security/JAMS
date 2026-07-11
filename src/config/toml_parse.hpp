#pragma once

#include "tomlcpp.h"
#include <iostream>
#include <vector>
#include <unordered_map>

class TOMLParser {
    public:
        TOMLParser(const std::string path);
        ~TOMLParser();

        static void error(const char* msg) {
            std::fprintf(stderr, "[TOML] ERROR: %s\n", msg);
            return;
        };

        static std::unordered_map<std::string, std::string> fetch_configs();

    private:
        bool load_configs();
        std::string path_;
        static toml::Result toml_results;
};