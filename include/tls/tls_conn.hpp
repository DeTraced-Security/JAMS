#pragma once

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <vector>

// Wraps a single SSL* with two memory BIOs so OpenSSL never touches the
// socket directly.  All encrypted I/O is owned by io_uring.
//
// Lifecycle:
//   1. Created when SmtpSession receives STARTTLS.
//   2. feed_encrypted() is called each time io_uring delivers ciphertext.
//   3. During the handshake, feed_encrypted() returns pending ciphertext
//      that must be sent back to the client (ServerHello etc.).
//   4. Once handshake_done() returns true, feed_encrypted() decrypts and
//      delivers plaintext via the on_plaintext callback.
//   5. encrypt() takes plaintext from the SMTP layer and returns ciphertext
//      to be handed to io_uring for sending.
//
//  Memory BIO layout:
//
//    ┌─────────────────────────────────┐
//    │           OpenSSL               │
//    │  rbio ◄── BIO_write(ciphertext) │  ← encrypted bytes from network
//    │  SSL_read() → plaintext         │  → delivered to SmtpSession
//    │  SSL_write(plaintext) →         │  ← called by SmtpSession
//    │  BIO_read(wbio) → ciphertext    │  → sent to network via io_uring
//    └─────────────────────────────────┘

class TlsConn {
    public:
        using PlaintextCB = std::function<void(std::span<const uint8_t>)>;

        TlsConn(SSL* ssl, PlaintextCB on_plaintext);
        ~TlsConn();

        TlsConn(const TlsConn&) = delete;
        TlsConn& operator=(const TlsConn&) = delete;

        [[nodiscard]]
        std::vector<uint8_t> feed_encryption(std::span<const uint8_t> cipher_in);

        [[nodiscard]]
        std::vector<uint8_t> encrypt(std::span<const uint8_t> plain_in);

        bool handshake_done() const {
            return handshake_done_;
        }

        std::string info() const;

    private:
        std::vector<uint8_t> drain_wbio();

        std::vector<uint8_t> drive_handshake();

        SSL* ssl_{nullptr};
        BIO* rbio_{nullptr};
        BIO* wbio_{nullptr};
        bool handshake_done_{false};
        PlaintextCB on_plaintext_;

        static constexpr size_t PLAIN_BUF = 16384;
        uint8_t plain_buf_[PLAIN_BUF];
};
