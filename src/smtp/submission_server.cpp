#include "submission_server.hpp"
#include "io/io_uring_loop.hpp"
#include "storage/maildir.hpp"
#include <cctype>
#include <iostream>
#include <sstream>

SubmissionServer::SubmissionServer(
    uint64_t conn_id, const std::string& remote_ip,
    IoUringLoop& loop, Auth::CredentialStore& store
) : conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop),
    sasl_(store) {
        reply(220, "mail.detraced.org ESMTP submission");
}

void SubmissionServer::on_tls_established() {    
    tls_active_ = true;
    
    // No banner needed here, EHLO is received after the handshake
    std::cout << "[Submission]: " << conn_id_ << " TLS handshake completed" << std::endl;
}

void SubmissionServer::on_data(std::span<const uint8_t> bytes) {
    for (uint8_t b : bytes) {
        if (state_ == State::Data) {
            // in DATA mode, accumulate the raw bytes
            // and detect teh EOD sequence: CRLF.CRLF
            line_buf_ += static_cast<char>(b);

            data_tail_ += static_cast<char>(b);
            if (data_tail_.size() > 5) {
                data_tail_.erase(0, data_tail_.size() - 5);
            }

            if (data_tail_ == "\r\n.\r\n") {
                env_.body = line_buf_.substr(
                    0, line_buf_.size() -5
                ); // remove the "\r\n.\r\n"
                line_buf_.clear();
                data_tail_.clear();

                if (deliver()) {
                    reply(250, "OK: Message Accepted");
                    state_ = State::Greeted;
                    env_ = {};
                } else {
                    reply(452, "Insufficient Storage");
                }
            }
        } else {
            // Command mode: buffer until LF
            if (b == '\n') {
                // Strip until CR isn't present
                if (!line_buf_.empty() && line_buf_.back() == '\r') {
                    line_buf_.pop_back();
                }

                process_line(line_buf_);
                line_buf_.clear();
            } else {
                line_buf_ += static_cast<char>(b);
                // Guard against long lines (RFC-5321 4.5.3)
                if (line_buf_.size() > 2048) {
                    reply(500, "Line too long");
                    line_buf_.clear();
                }
            }
        }
    }
}

void SubmissionServer::process_line(std::string_view line) {
    if (line.empty()) {
        return;
    }

    // If SASL is in exchange, the line will be continuous, not a command
    if (sasl_.in_progress()) {
        // "*" Cancels the exchange
        auto resp = sasl_.respond(std::string(line));
        reply (resp.code, resp.message);

        if (resp.code == 235) {
            state_ = State::Authenticated;
        }

        return;
    }


    // Continue like SMTP
    auto sp = line.find(' ');
    std::string verb(line.substr(0, sp));
    std::string_view arg = (sp != std::string_view::npos) ? line.substr(sp + 1) : std::string_view("");

    // normalise verb to upper-case
    for (char& c : verb) {
        c = static_cast<char>(std::toupper(c));
    }

    std::cout << "[submission: " << conn_id_ << "]" << line << std::endl;

    if (verb == "EHLO") {
        cmd_ehlo(arg);
    } else if (verb == "HELO") {
        cmd_helo(arg);
    } else if (verb == "MAIL") {
        cmd_mail(arg);
    } else if (verb == "RCPT") {
        cmd_rcpt(arg);
    } else if (verb == "DATA") {
        cmd_data();
    } else if (verb == "RSET") {
        cmd_rset();
    } else if (verb == "NOOP") {
        cmd_noop();
    } else if (verb == "QUIT") {
        cmd_quit();
    } else if (verb == "VRFY" || verb == "EXPN") {
        reply(502, "Command not implemented");
    } else if (verb == "AUTH") {
        cmd_auth(arg);
    } else if (verb == "STARTTLS") {
        cmd_starttls();
    }
    else {
        reply(500, "Command unrecognised");
    }
}

void SubmissionServer::cmd_ehlo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    state_ = State::Greeted;

    std::vector<std::string> caps = {
        "mail.detraced.org greets " + client_helo_,
        "8BITMIME",
        "PIPELINING",
        "SIZE 52428800"
    };

    if (loop_.is_tls_active(conn_id_)) {
        caps.push_back("AUTH PLAIN LOGIN");
    } else {
        /// Note: kept for Outlook compat.
        caps.push_back("STARTTLS"); 
        // We reject AUTH without TLS, so no need to guard here
        caps.push_back("AUTH PLAIN LOGIN");
    }

    reply_multiline(250, caps);
}

void SubmissionServer::cmd_starttls() {
    if (loop_.is_tls_active(conn_id_)) {
        reply(503, "TLS Already Active");
        return;
    }

    reply(220, "Ready to start TLS");
    env_ = {};
    state_ = State::Greeted;

    line_buf_.clear();
    loop_.upgrade_tls(conn_id_);
}

void SubmissionServer::cmd_auth(std::string_view arg) {
    if (!loop_.is_tls_active(conn_id_)) {
        reply(538, "5.7.11 Encryption required for AUTH");
        return;
    }

    if (state_ == State::Authenticated) {
        reply(503, "Already authenticated");
        return;
    }

    if (state_ != State::Greeted) {
        reply(503, "Bad sequence of commands");
        return;
    }

    auto sp = arg.find(' ');
    std::string mechanism(arg.substr(0, sp));
    std::string initial = (sp != std::string_view::npos) ? std::string(arg.substr(sp+1)) : "";

    auto resp = sasl_.begin(mechanism, initial);
    reply(resp.code, resp.message);

    if (resp.code == 235) {
        state_ = State::Authenticated;
    } else if (resp.code == 334) {
        // Challenge has been sent, we wait on greeted until it's complete
        state_ = State::Greeted;
    }
}

void SubmissionServer::cmd_helo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    reply(250, "mail.detraced.org");
    state_ = State::Greeted;
}

void SubmissionServer::cmd_mail(std::string_view arg) {
    if (state_ != State::Authenticated) {
        if (state_ == State::Greeted) {
            reply(530, "5.7.0 Authentication Required");
        } else {
            reply(503, "Bad sequence of commands");
        }

        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 5) != "FROM:") {
        reply(501, "Syntax: MAIL FROM:<address>");
        return;
    }

    env_.mail_from = std::string(extract_address(arg.substr(5)));
    state_ = State::Mail;
    reply(250, "OK");
}

void SubmissionServer::cmd_rcpt(std::string_view arg) {
    if (state_ != State::Mail && state_ != State::Rcpt) {
        reply(503, "Bad Sequence of Commands");
        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0,3) != "TO:") {
        reply(501, "Syntax: RCPT TO:<addr>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(3)));

    if (addr.empty()) {
        reply(501, "Empty Recipient");
        return;
    }

    // RFC 5321 4.5.3: max 100
    if (env_.rcpt_to.size() >= 100) {
        reply(452, "Too Many Recipients");
        return;
    }

    env_.rcpt_to.push_back(addr);
    state_ = State::Rcpt;
    reply(250, "OK");
}

void SubmissionServer::cmd_data() {
    if (state_ != State::Rcpt) {
        reply(503, "Bad sequence of commands");
        return;
    }

    reply(354, "Start mail input; end with <CRLF>.<CRLF>");
    state_ = State::Data;
    line_buf_.clear();
    data_tail_.clear();
}

void SubmissionServer::cmd_rset() {
    env_ = {};

    state_ = sasl_.authenticated() ? State::Authenticated : State::Greeted;
    reply(250, "OK");
}

void SubmissionServer::cmd_noop() {
    reply(250, "OK");
}

void SubmissionServer::cmd_quit() {
    reply(221, "mail.detraced.org closing connection");
    state_ = State::Done;
    pending_close_ = true;
    loop_.submit_close(conn_id_);
}

bool SubmissionServer::deliver() {
    // TODO: Encrypt before writing
    bool all_ok = true;
    
    for (const auto& rcpt : env_.rcpt_to) {
        // Extract local/account name (before @)
        auto at = rcpt.find('@');
        std::string local = (at != std::string::npos) ? rcpt.substr(0, at) : rcpt;

        MailDir mdir("/var/mail/vhosts/" + local);
        if (!mdir.deliver(env_.mail_from, rcpt, env_.body)) {
            std::cerr << "[deliver] failed for " << rcpt << std::endl;
            all_ok = false;
        }
    }

    return all_ok;
}

void SubmissionServer::reply(int code, std::string_view text) {
    std::string line(std::to_string(code) + " " + std::string(text));
    line += "\r\n";
    
    std::cout << "[submission:" << conn_id_ << "] > " << text << std::endl;

    std::vector<uint8_t> buf(line.begin(), line.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

void SubmissionServer::reply_multiline(int code, const std::vector<std::string> &lines) {
    // RFC 5321 4.2.1 Intermediate lines use "<code>-"
    std::string code_str = std::to_string(code);
    std::string out;

    for (size_t i = 0; i < lines.size(); ++i) {
        bool last = (i + 1 == lines.size());
        out += code_str;
        out += (last ? ' ' : '-');
        out += lines[i];
        out += "\r\n";
    }

    std::cout << "[submission:" << conn_id_ << "] > " << code_str << " (multiline, " << lines.size() << " lines)\n";

    std::vector<uint8_t> buf(out.begin(), out.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

std::string_view SubmissionServer::trim(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");
    
    if (start == std::string_view::npos) {
        return{};
    }

    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

std::string_view SubmissionServer::extract_address(std::string_view arg) {
    arg = trim(arg);

    // Strip an ESMTP parameters after the address
    auto space = arg.find(' ');
    if (space != std::string_view::npos) {
        arg = arg.substr(0, space);
    }

    if (!arg.empty() && arg.front() == '<' && arg.back() == '>') {
        arg = arg.substr(1, arg.size() - 2);
    }

    return trim(arg);
}
