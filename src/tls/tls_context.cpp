#include "tls/tls_context.hpp"
#include "globals.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdexcept>
#include <string>

static std::string ssl_error_string()
{
    char buf[256] = {};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    return buf;
}

TLS::Context::Context(const std::string& cert, const std::string& key)
{
    // One-time init
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // TLS1.2+ server context
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_)
    {
        throw std::runtime_error("SSL_CTX_new failed: " + ssl_error_string());
    }

    // enforce TLS 1.2 min
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

    SSL_CTX_set_options(
        // CRIME vuln - We disable compression
        ctx_, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_COMPRESSION);

    SSL_CTX_set_cipher_list(ctx_,
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256");

    if (SSL_CTX_use_certificate_chain_file(ctx_, cert.c_str()) != 1)
    {
        throw std::runtime_error("load cert (" + cert + "): " + ssl_error_string());
    }

    if (SSL_CTX_use_PrivateKey_file(ctx_, key.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        throw std::runtime_error("load key (" + key + "): " + ssl_error_string());
    }

    if (SSL_CTX_check_private_key(ctx_) != 1)
    {
        throw std::runtime_error("cert/key mismatch: " + ssl_error_string());
    }
}

TLS::Context::~Context()
{
    if (ctx_)
    {
        SSL_CTX_free(ctx_);
    }
}

SSL* TLS::Context::new_server_ssl() const
{
    SSL* ssl = SSL_new(ctx_);

    if (!ssl)
    {
        throw std::runtime_error("SSL_new failed: " + ssl_error_string());
    }

    /// This is just a sanity check, we verify our CA already before making the server
    /// This just forces the CA hostname to match the server hostname.
    if (SSL_set_tlsext_host_name(ssl, get_hostname().c_str()) != 1) {
        throw std::runtime_error("[FATAL] [TLS] failed to set CA hostname" + ssl_error_string());
    }

    BIO* rbio = BIO_new(BIO_s_mem()); /// network BIO (input)
    BIO* wbio = BIO_new(BIO_s_mem()); /// OpenSSL BIO (output)

    if (!rbio || !wbio) {
        if (rbio) {
            BIO_free(rbio);
        }

        if (wbio) {
            BIO_free(wbio);
        }

        SSL_free(ssl);
        throw std::runtime_error("[FATAL] [TLS] BIO_new failed: " + ssl_error_string());
    }

    /// Returns 0/EOF when drained, "connection closed," so we feed it -1 (retry)
    /// as we increment it
    BIO_set_mem_eof_return(rbio, -1);
    BIO_set_mem_eof_return(wbio, -1);


    /// Hand over control to OpenSSL
    SSL_set_bio(ssl, rbio, wbio);

    return ssl;
}
