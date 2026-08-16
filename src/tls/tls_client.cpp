#include "tls/tls_client.hpp"
#include "globals.hpp"

#include <openssl/err.h>
#include <stdexcept>

static std::string ssl_error_string()
{
    char buf[256]{};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

TLS::ClientContext::ClientContext()
{
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        throw std::runtime_error("[FATAL] [TLS] SSL_CTX_new (client) failed: " + ssl_error_string());
    }

    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx_, SSL_OP_NO_COMPRESSION);

    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);

    if (SSL_CTX_set_default_verify_paths(ctx_) != 1) {
        throw std::runtime_error("[FATAL] [TLS] (client) failed to load default CA verify paths");
    }
}

TLS::ClientContext::~ClientContext()
{
    if (ctx_)
    {
        SSL_CTX_free(ctx_);
    }
}

SSL* TLS::ClientContext::handshake(int fd, const std::string& sni_hostname) const
{
    SSL* ssl = SSL_new(ctx_);
    if (!ssl) {
        logger.error("[TLS] [CLIENT] SSL_new failed: " + ssl_error_string());
        return nullptr;
    }

    SSL_set_tlsext_host_name(ssl, sni_hostname.c_str());
    SSL_set_fd(ssl, fd);

    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        logger.error("[TLS] [CLIENT] SSL_connect failed for: " + sni_hostname + " (err=" + std::to_string(err) + "): " + ssl_error_string());

        SSL_free(ssl);
        return nullptr;
    }

    logger.debug("[TLS] [CLIENT] handshake completed with: " + sni_hostname + ": " + std::string(SSL_get_version(ssl)) + " / " + std::string(SSL_get_cipher(ssl)));

    return ssl;
}
