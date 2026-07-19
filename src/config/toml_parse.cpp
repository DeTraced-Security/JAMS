#include "toml_parse.hpp"
#include <filesystem>

TOMLParser::TOMLParser(const std::string path) {
    path_ = path;
    const bool is_ok = load_configs();
    
    if (!is_ok) {
        error("Terminating JAMS, please verify the correctness of the server.toml file");
        exit(1);
    }
}

TOMLParser::~TOMLParser() {
    
}

bool TOMLParser::load_configs() {
    const std::string absolute_path = std::filesystem::weakly_canonical(path_).string();
    const bool path_ok = std::filesystem::is_regular_file(absolute_path);

    if (!path_ok) {
        TOMLParser::error(std::format("Unable to verify config file path provided!\nFile given: {}", absolute_path).c_str());
        return false;
    }

    toml_results = toml::parse_file_ex(absolute_path.c_str());
    if (!toml_results->ok()) {
        TOMLParser::error(toml_results->errmsg());
        return false;
    }

    return true;
}

std::unordered_map<std::string, std::string> TOMLParser::fetch_configs() {
    std::unordered_map<std::string, std::string> results = {};

    std::string hostname, mailroot, smtp, submissions, imap4, imap4s, db_path;

    try {
        hostname = toml_results->get({"server", "hostname"})->as_str().value();
        mailroot = toml_results->get({"server", "mailroot"})->as_str().value();

        smtp = toml_results->get({"ports", "smtp"})->as_str().value();
        submissions = toml_results->get({"ports", "submissions"})->as_str().value();
        imap4 = toml_results->get({"ports", "imap4"})->as_str().value();
        imap4s = toml_results->get({"ports", "imap4s"})->as_str().value();

        db_path = toml_results->get({"database", "dbpath"})->as_str().value();
    } catch (const std::bad_optional_access& ex) {
        error("missing or invalid server/ports/database properties in config");
    }

    results.insert({
        { "hostname", hostname },
        { "mailroot", mailroot },
        { "smtp_port", smtp },
        { "submissions_port", submissions },
        { "imap4_port", imap4 },
        { "imap4s_port", imap4s },
        { "db_path", db_path }
    });

    return results;
}
