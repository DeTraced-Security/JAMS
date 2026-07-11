#pragma once

#include <string>
#include <filesystem>

class MailDir {
    public:
        explicit MailDir(std::string path);

        /// @brief Safety check against malicious addresses
        /// @param local 
        /// @return 
        static bool is_safe(std::string& addr);

        /// @brief Ensures the directories are valid and usable
        /// @return 
        bool ensure_dirs();

        /// @brief Delivers the email from the wire onto the disk
        /// @param mail_from 
        /// @param rcpt_to 
        /// @param body 
        /// @return 
        bool deliver(const std::string& mail_from,
            const std::string& rcpt_to,
            const std::string& body);
        
    private:
        std::string unique_filename(size_t body_size) const;
        std::filesystem::path base_;
};
