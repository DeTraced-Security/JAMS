#include "cred_store.hpp"
#include "config/toml_parse.hpp"

class Aliases {
    public:
        explicit Aliases(Auth::CredentialStore& db) : db_(db.handle()) {};

        /// @brief Returns target username if address is an active alias,
        /// otherwise returns `address` unchanged.
        /// @param address 
        /// @return 
        std::string resolve(const std::string& address);
        
        /// @brief 
        /// @param alias 
        /// @param username 
        /// @param expiry 
        /// @param receives_from 
        /// @return 
        bool add(
            const std::string& alias, const std::string& username,
            uint64_t expiry = 0, const std::string& receives_from = "*"
        );
        
        /// @brief 
        /// @param alias 
        /// @return 
        bool remove(const std::string& alias);

        /// @brief 
        /// @param username 
        /// @return 
        std::vector<std::string> list_for(const std::string& username);

    private:
        sqlite3* db_; // Borrowing from CredStore
};
