#include "maildir.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

MailDir::MailDir(std::string base_path) : base_(std::move(base_path)) {};

bool MailDir::ensure_dirs() {
    namespace fs = std::filesystem;

    std::error_code ec;
    for (const char* sub : {"tmp", "new", "cur"}) {
        fs::create_directories(base_ / sub, ec);
        if (ec) {
            std::cerr << "[maildir] create_directories(" 
                << (base_ / sub) << "): " << ec.message() << std::endl;
            
            return false;
        }
    }

    return true;
}

bool MailDir::deliver(
    const std::string& mail_from,
    const std::string& rcpt_to, 
    const std::string& body
) {
    if (!ensure_dirs()) {
        return false;
    }

    // Building the mesasge
    auto now_tp = std::chrono::system_clock::now();
    auto now_t = std::chrono::system_clock::to_time_t(now_tp);
    char date_buf[64] = {};
    std::tm tm_buf{};

    if (localtime_r(&now_t, &tm_buf) == nullptr) {
        std::cerr << "[MailDir] localtime_r failed: " << strerror(errno) << std::endl;
        return false;
    }    

    // RFC-2822 date format:
    std::strftime(
        date_buf, sizeof(date_buf), 
        "%a, %d %b %Y %H:%M:%S %z",
        &tm_buf
    );

    std::string message = "Received: from unknown (HELO unknown)\r\n"
        "   by mail.detraced.org from <" + mail_from + "> for <" + rcpt_to + ">; \r\n"
        "   " + date_buf + "\r\n" + body;

    // Create file and write to tmp/
    std::string fname = unique_filename(message.size());

    auto tmp_path = base_ / "tmp" / fname;
    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            std::cerr << "[maildir] open(" << tmp_path << "): "
                << strerror(errno) << std::endl;
            return false;
        }

        ofs.write(message.data(), static_cast<std::streamsize>(message.size()));
        if (!ofs) {
            std::cerr << "[maildir] write failed for " << tmp_path << std::endl;
            return false;
        }

        ofs.flush();
    }

    // Atomically move to new/
    auto new_path = base_ / "new" / fname;
    std::error_code ec;
    std::filesystem::rename(tmp_path, new_path, ec);
    
    if (ec) {
        std::cerr << "[maildir] rename to new/ failed: " << ec.message() << std::endl;
        std::filesystem::remove(tmp_path, ec);
        return false;
    }

    std::cout << "[maildir] delivered to " << new_path << std::endl;
    return true;
}

// Filename Generation
// Format: <sec>.<pid>.<hostname>,S=<size>:2,
//
// The hostname component is capped at 64 chars and dots are replaced with
// underscores (Maildir spec recommendation for portability).
std::string MailDir::unique_filename(size_t body_size) const {
    using namespace std::chrono;

    auto now_us = duration_cast<microseconds>(
        system_clock::now().time_since_epoch()
    ).count();
    long sec = static_cast<long>(now_us / 1'000'000);
    long usec = static_cast<long>(now_us % 1'000'000);
    pid_t pid = ::getpid();

    char hostname[64] = "localhost";

    if (::gethostname(hostname, sizeof(hostname)) != 0) {
        std::cerr << "[maildir] gethostname failed: " << std::strerror(errno)
            << "; using fallback hostname 'localhost'" << std::endl;
    } else {
        hostname[sizeof(hostname) - 1] = '\0';
    }

    // Replace dots with underscores
    for (char* p = hostname; *p; ++p) {
        if (*p == '.') {
            *p = '_';
        }
    }

    std::ostringstream oss;
    oss << sec
        << "." << usec
        << "." << pid
        << "." << hostname
        << ",S=" << body_size
        << ":2,";   // Maildir++ flags field (empty = no flags)
    
    return oss.str();
}

