#include "io/io_uring_loop.hpp"
#include "auth/cred_store.hpp"
#include "smtp/smtp_session.hpp"
#include "smtp/submission_server.hpp"
#include "imap/imap_session.hpp"
#include "config/toml_parse.hpp"
#include "globals.hpp"
#include <csignal>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <iostream>

// build info
static constexpr const char* JAMS_VERSION = "0.0.1-alpha";
static const std::string JAMS_HOSTNAME = get_hostname();

// Signal handling
volatile sig_atomic_t g_shutdown = 0;
static void handle_signal(int sig) {
    g_shutdown = 1;

    // Write sig number to stderr without ynsafe async functions
    const char* msg = (sig == SIGINT) 
        ? "\n[JAMS] SIGINT received... Shutting down\n" 
        : "\n[JAMS] SIGTERM received... Shutting down\n";

    (void)write(STDERR_FILENO, msg, strlen(msg));
}

static void help(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]"
        << "\n"
        << "Server Configuration are made via the `./config/server.toml` file"
        << "\n"
        << "notes:\n"
        << "  ports below 1024 require CAP_NET_BIND_SERVICE or root\n"
        << "  set with: sudo setcap cap_net_bind_service=+ep ./mailserver" << std::endl;
}

static void banner() {
    std::cout
        << "┌─────────────────────────────────────────┐\n"
        << "│   JAMS — Just Another Mail Server       │\n"
        << "│   version " << JAMS_VERSION
        << "                   │\n"
        << "│   github.com/DeTraced-Security/JAMS     │\n"
        << "└─────────────────────────────────────────┘\n";
}

struct Config {
    uint16_t smtp_port;
    uint16_t submission_port;
    uint16_t imap4_secure_port;
    uint16_t imap4_port;
    std::string db_path;
};


int main(int argc, char* argv[]) {
    Config cfg;

    for (auto& p : configs) {
        if (p.first == "smtp") {
            cfg.smtp_port = std::stoi(p.second);
        }
        if (p.first == "imap4") {
            cfg.imap4_port = std::stoi(p.second);
        }
        if (p.first == "imap4s") {
            cfg.imap4_secure_port = std::stoi(p.second);
        }
        if (p.first == "submissions") {
            cfg.submission_port = std::stoi(p.second);
        }
    }

    banner();

    // Signal monitor setup
    struct sigaction sig_action{};
    sig_action.sa_handler = handle_signal;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sig_action, nullptr);
    sigaction(SIGTERM, &sig_action, nullptr);

    // SIGPIPE
    signal(SIGPIPE, SIG_IGN);

    // Credential Storage
    std::cout << "[JAMS] Opening user database: " << cfg.db_path << std::endl;
    Auth::CredentialStore cred_store(cfg.db_path);

    if (cred_store.db_ == nullptr) {
        std::cerr << "[JAMS - FATAL] Could not open database: "
            << cfg.db_path << "\n"
            << "        create the directory first:\n"
            << "        sudo mkdir -p /var/lib/jams\n"
            << "        sudo chown $USER /var/lib/jams" << std::endl;
        
        return 1;
    }

    // SMTP inbound loop
    std::cout << "[JAMS] Starting SMTP inbound on port: " << cfg.smtp_port << std::endl;
    std::cout << "[JAMS] Hostname: " << JAMS_HOSTNAME << std::endl;
    std::cout << "[JAMS] Ready\n" << std::endl;

    std::atomic<bool> server_failed{false};

    std::thread smtp_thread([&]() {
        try {
            IoUringLoop smtp_loop(cfg.smtp_port, [](uint64_t id, const std::string& ip, IoUringLoop& loop) {
                return std::make_unique<SMTPSession>(id, ip, loop);
            });
            smtp_loop.run();
        } catch (const std::exception& ex) {
            std::cerr << "[JAMS - FATAL] SMTP loop: " << ex.what() << std::endl; 
            server_failed = true;
            raise(SIGTERM);  
        }
    });

    std::thread submission_thread([&]() {
        try {
            IoUringLoop submission_loop(cfg.submission_port, [&cred_store](uint64_t id, const std::string& ip, IoUringLoop& loop) {
                return std::make_unique<SubmissionServer>(id, ip, loop, cred_store);
            });
            submission_loop.run();
        } catch(const std::exception& ex) {
            std::cerr << "[JAMS - FATAL] Submission loop: " << ex.what() << std::endl;
            server_failed = true;
            raise(SIGTERM);
        }
    });

    std::thread imap4_thread([&]() {
        try {
            IoUringLoop imap4_loop(cfg.imap4_port, [&cred_store](uint64_t id, const std::string& ip, IoUringLoop& loop) {
                return std::make_unique<IMAPSession>(id, ip, loop, cred_store, get_mailroot());
            });
            imap4_loop.run();
        } catch (const std::exception& ex) {
            std::cerr << "[JAMS - FATAL] IMAP4 loop: " << ex.what() << std::endl;
            server_failed = true;
            raise(SIGTERM);
        }
    });

    std::thread imap4_secure_thread([&]() {
        try {
            IoUringLoop imap4_secure_loop(cfg.imap4_secure_port, [&cred_store](uint64_t id, const std::string& ip, IoUringLoop& loop) {
                return std::make_unique<IMAPSession>(id, ip, loop, cred_store, get_mailroot());
            });
            imap4_secure_loop.run();
        } catch (const std::exception& ex) {
            std::cerr << "[JAMS - FATAL] IMAP4 Secure loop: " << ex.what() << std::endl;
            server_failed = true;
            raise(SIGTERM);
        }
    });

    smtp_thread.join();
    submission_thread.join();
    imap4_thread.join();
    imap4_secure_thread.join();

    std::cout << "[JAMS] Shutdown complete" << std::endl;
    return server_failed ? EXIT_FAILURE : 0;
}