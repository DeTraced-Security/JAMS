#pragma once

#include <string>
#include <filesystem>

class MailDir {
    public:
        explicit MailDir(std::string path);

        /// @brief Ensures the directories are valid and usable
        /// @return 
        bool ensure_dirs();

        /// @brief Delivers the email from the wire onto the disk
        /// @param mail_from 
        /// @param rcpt_to 
        /// @param body 
        /// @return 
        std::optional<std::string> deliver(const std::string& mail_from,
            const std::string& rcpt_to,
            const std::string& body);
        
    private:
        std::string unique_filename(size_t body_size) const;
        std::filesystem::path base_;
};
