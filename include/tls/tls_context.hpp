#pragma once

#include <openssl/ssl.h>
#include <string>
#include <memory>

namespace TLS {
    class Context {
        public:
            Context(const std::string& cert, const std::string& key);
            ~Context();

            Context(const Context&) = delete;
            Context& operator=(const Context&) = delete;

            SSL* new_server_ssl() const;

            SSL_CTX* ctx() const {
                return ctx_;
            }

        private:
            SSL_CTX* ctx_{nullptr};
    };
};
