#pragma once

#include <string>
#include <filesystem>

class MailDir {
    public:
        explicit MailDir(std::string path);

        bool ensure_dirs();
        bool deliver(const std::string& mail_from,
            const std::string& rcpt_to,
            const std::string& body);
        
    private:
        std::string unique_filename(size_t body_size) const;
        std::filesystem::path base_;
};
