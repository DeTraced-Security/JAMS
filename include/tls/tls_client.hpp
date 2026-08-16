#pragma once

#include <openssl/ssl.h>
#include <string>

namespace TLS {

    /**
     * @brief Blocking client-side TLS for outbound relay connections
     * It's opportunistic STARTTLS or rMTA (remote MTA).
     */
    class ClientContext {
    public:
        ClientContext();
        ~ClientContext();

        ClientContext(const ClientContext&) = delete;
        ClientContext& operator=(const ClientContext&) = delete;

        /**
         * @brief Creates a new SSL pointer bound directly to fds (blocking)
         * and performs a synchronous handshake with the client.
         *
         * @param fd
         * @param sni_hostname
         * @return SSL*
         */
        SSL* handshake(int fd, const std::string& sni_hostname) const;

    private:
        SSL_CTX* ctx_ = nullptr;
    };
};
