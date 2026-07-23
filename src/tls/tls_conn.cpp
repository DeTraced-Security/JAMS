#include "tls_conn.hpp"
#include "globals.hpp"
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>

TlsConn::TlsConn(SSL* ssl, PlaintextCB on_plaintext) : ssl_(ssl), on_plaintext_(on_plaintext) {
    rbio_ = BIO_new(BIO_s_mem());
    wbio_ = BIO_new(BIO_s_mem());

    if (!rbio_  || !wbio_) {
        logger.error("[FATAL] [TLS_CONN] BIO_new failed");
        throw std::runtime_error("BIO_new failed");
    }

    SSL_set_bio(ssl_, rbio_, wbio_);
    SSL_set_accept_state(ssl_);
}

TlsConn::~TlsConn() {
    if (ssl_) {
        SSL_free(ssl_);
    }
}

std::vector<uint8_t> TlsConn::feed_encryption(std::span<const uint8_t> cipher_in) {
    if (!cipher_in.empty()) {
        int written = BIO_write(rbio_, cipher_in.data(), static_cast<int>(cipher_in.size()));

        if (written <= 0) {
            logger.error("[FATAL] [TLS_CONN] BIO_write to rbio failed");
            throw std::runtime_error("BIO_write to rbio failed");
        }
    }

    if (!handshake_done_) {
        return drive_handshake();
    }

    std::vector<uint8_t> pending_cipher; // renegotiation

    for (;;) {
        int n = SSL_read(ssl_, plain_buf_, static_cast<int>(PLAIN_BUF));

        if (n > 0) {
            on_plaintext_(std::span<const uint8_t>(plain_buf_, static_cast<size_t>(n)));
            continue;
        }

        int err = SSL_get_error(ssl_, n);

        if (err == SSL_ERROR_WANT_READ) {
            break; // need more cipher text
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            break; // clean exit/shutdown
        } else if (err == SSL_ERROR_WANT_WRITE) {
            // TLS Session needs to send data
            auto out = drain_wbio();
            pending_cipher.insert(pending_cipher.end(), out.begin(), out.end());
            
            break;
        } else  if (err == SSL_ERROR_WANT_X509_LOOKUP) {
            continue;
        } else {	
            // fatal error but not crashable
            char buf[256] = {};
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));

            logger.error("[FATAL] [TLS_CONN] SSL_read error: " + std::string(buf));
            break;
        }
    }

    auto wbio_out = drain_wbio();
    if (!wbio_out.empty()) {
        pending_cipher.insert(pending_cipher.end(), wbio_out.begin(), wbio_out.end());
    }

    return pending_cipher;
}

std::vector<uint8_t> TlsConn::encrypt(std::span<const uint8_t> plain_in) {
    if (!handshake_done_) {
        logger.error("[FATAL] [TLS_CONN] encrypt called before handshake");
        throw std::logic_error("TlsConn::encrypt called before handshake");
    }

    int n = SSL_write(ssl_, plain_in.data(), static_cast<int>(plain_in.size()));

    if (n <= 0) {
        int err = SSL_get_error(ssl_, n);
        char buf[256] = {};

        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));

        logger.error("[FATAL] [TLS_CONN] SSL_write failed (err=" + std::to_string(err) + "): " + std::string(buf));
        throw std::runtime_error(
            std::string("SSL_write failed (err=") + std::to_string(err) + "): " + buf
        );
    }

    return drain_wbio();
}

std::string TlsConn::info() const {
    std::ostringstream oss;
    oss << SSL_get_version(ssl_) << " / " << SSL_get_cipher(ssl_);

    return oss.str();
}

std::vector<uint8_t> TlsConn::drain_wbio() {
    std::vector<uint8_t> out;
    uint8_t tmp[4096];

    int n;

    while ((n = BIO_read(wbio_, tmp, sizeof(tmp))) > 0) {
        out.insert(out.end(), tmp, tmp + n);
    }

    return out;
}

std::vector<uint8_t> TlsConn::drive_handshake() {
    int ret = SSL_do_handshake(ssl_);

    auto out = drain_wbio();

    if (ret == 1) {
        handshake_done_ = true;
        logger.debug("[TLS] Handshake completed: " + info());

        return out;
    }

    int err = SSL_get_error(ssl_, ret);

    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Normal, sometimes more roundtrips are needed
        return out;
    }

    char buf[256] = {};

    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    logger.error("[TLS] Handshake error:\n\t" + std::string(buf));
    
    return out;
}
