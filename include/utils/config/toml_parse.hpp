#pragma once

#include "tomlcpp.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <optional>

namespace Utils {
    class TOMLParser {
    public:
        explicit TOMLParser(const std::string path);
        ~TOMLParser();

        static void error(const char* msg);

        std::unordered_map<std::string, std::string> fetch_configs();

    private:
        bool load_configs();
        std::string path_;
        std::optional<toml::Result> toml_results;

    };
};
