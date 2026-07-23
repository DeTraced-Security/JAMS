#include "cred_store.hpp"
#include "config/toml_parse.hpp"

struct AliasPolicy {
    std::optional<int64_t> expires_at;
    std::optional<int> max_uses;
    std::optional<int> auto_delete_after; // seconds
};

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
        bool add(const std::string& alias, const std::string& username, const AliasPolicy& policy = {});
        
        /// @brief 
        /// @param alias 
        /// @return 
        bool remove(const std::string& alias);

        /// @brief 
        /// @param username 
        /// @return 
        std::vector<std::string> list_for(const std::string& username);

        bool add_allowed_domain(const std::string& alias, const std::string& domain);

        bool is_domain_allowed(const std::string& alias, const std::string& sender_domain);

        bool accept_and_consume(const std::string& alias);

        void schedule_purge(const std::string& alias, const std::string& username, const std::string& maildir);

        void reap_expired();

        std::vector<std::tuple<int64_t, std::string>> due_purges();

        void mark_purged(int64_t queue_id);

    private:
        sqlite3* db_; // Borrowing from CredStore
};
