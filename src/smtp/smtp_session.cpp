#include "smtp_session.hpp"
#include "io/io_uring_loop.hpp"
#include "storage/maildir.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <span>

SMTPSession::SMTPSession(
    uint64_t conn_id, std::string remote_ip, 
    IoUringLoop& loop
): conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop) {
    // RFC-5321 4.2: Send 220 Banner on connect
    reply_code(220, "mail.detraced.org ESMTP mailserver/0.1");
    state_ = SMTPState::Greeted; // Wait for EHLO
}

void SMTPSession::on_data(std::span<const uint8_t> bytes) {
    for (uint8_t b : bytes) {
        if (state_ == SMTPState::Data) {
            // in DATA mode, accumulate the raw bytes
            // and detect teh EOD sequence: CRLF.CRLF
            line_buf += static_cast<char>(b);

            data_tail_ += static_cast<char>(b);
            if (data_tail_.size() > 5) {
                data_tail_.erase(0, data_tail_.size() - 5);
            }

            if (data_tail_ == "\r\n.\r\n") {
                env_.body = line_buf.substr(
                    0, line_buf.size() -5
                ); // remove the "\r\n.\r\n"
                line_buf.clear();
                data_tail_.clear();

                if (deliver()) {
                    reply_code(250, "OK: Message Accepted");
                    state_ = SMTPState::Greeted;
                    env_ = {};
                } else {
                    reply_code(452, "Insufficient Storage");
                }
            }
        } else {
            // Command mode: buffer until LF
            if (b == '\n') {
                // Strip until CR isn't present
                if (!line_buf.empty() && line_buf.back() == '\r') {
                    line_buf.pop_back();
                }

                process_line(line_buf);
                line_buf.clear();
            } else {
                line_buf += static_cast<char>(b);
                // Guard against long lines (RFC-5321 4.5.3)
                if (line_buf.size() > 2048) {
                    reply_code(500, "Line too long");
                    line_buf.clear();
                }
            }
        }
    }
}

void SMTPSession::process_line(std::string_view line) {
    if (line.empty()) {
        return;
    }

    auto sp = line.find(' ');
    std::string verb(line.substr(0, sp));
    std::string_view arg = (sp != std::string_view::npos) ? line.substr(sp + 1) : std::string_view("");

    // normalise verb to upper-case
    for (char& c : verb) {
        c = static_cast<char>(std::toupper(c));
    }

    std::cout << "[smtp: " << conn_id_ << "]" << line << std::endl;

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
    } else if (verb == "STARTTLS") {
        cmd_starttls();
    } else {
        reply_code(500, "Command unrecognised");
    }
}

void SMTPSession::cmd_ehlo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};

    reply_multiline(250, {
        "mail.detraced.org greets " + client_helo_,
        "8BITMIME",
        "PIPELINING",
        "SIZE 52428800",   // 50 MB max message size
        "STARTTLS",
    });
    state_ = SMTPState::Greeted;
}

void SMTPSession::cmd_helo(std::string_view arg) {
    client_helo_ = std::string(trim(arg));
    env_ = {};
    reply_code(250, "mail.detraced.org");
    state_ = SMTPState::Greeted;
}

void SMTPSession::cmd_mail(std::string_view arg) {
    if (state_ != SMTPState::Greeted) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    // Expect: FROM:<addr> [params]
    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0, 5) != "FROM:") {
        reply_code(501, "Syntax: MAIL FROM:<addr>");
        return;
    }

    env_.mail_from  = std::string(extract_address(arg.substr(5)));
    state_ = SMTPState::Mail;
    reply_code(250, "OK");
}

void SMTPSession::cmd_rcpt(std::string_view arg) {
    if (state_ != SMTPState::Mail && state_ != SMTPState::RCPT) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    std::string upper(arg);
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(c));
    }

    if (upper.substr(0,3) != "TO:") {
        reply_code(501, "Syntax: RCPT TO:<addr>");
        return;
    }

    auto addr = std::string(extract_address(arg.substr(3)));

    if (addr.empty()) {
        reply_code(501, "Empty Recipient");
        return;
    }

    // RFC 5321 4.5.3: max 100
    if (env_.rcpt_to.size() >= 100) {
        reply_code(452, "Too Many Recipients");
        return;
    }

    env_.rcpt_to.push_back(addr);
    state_ = SMTPState::RCPT;
    reply_code(250, "OK");
}

void SMTPSession::cmd_data() {
    if (state_ != SMTPState::RCPT) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    reply_code(354, "Start mail input; end with <CLRF>.<CLRF>");
    state_ = SMTPState::Data;
    line_buf.clear();
    data_tail_.clear();
}

void SMTPSession::cmd_rset() {
    env_ = {};
    state_ = SMTPState::Greeted;
    reply_code(250, "OK");
}

void SMTPSession::cmd_noop() {
    reply_code(250, "OK");
}

void SMTPSession::cmd_quit() {
    reply_code(221, "mail.detraced.org closing connection");
    state_ = SMTPState::Done;
    pending_close_ = true;
}

void SMTPSession::cmd_starttls() {
    if (state_ == SMTPState::Data) {
        reply_code(503, "Bad Sequence of Commands");
        return;
    }

    // RFC 3207: send 220 then upgrade
    // after HELO, no more SMTP until TLS is started
    reply_code(220, "Ready to start TLS");

    // Reset the sessions state
    env_ = {};
    state_ = SMTPState::Greeted;
    line_buf.clear();

    // Hand off to the loop
    loop_.upgrade_tls(conn_id_);
}

bool SMTPSession::deliver() {
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

void SMTPSession::reply(std::string_view text) {
    std::string line(text);
    line += "\r\n";
    
    std::cout << "[smtp:" << conn_id_ << "] > " << text << std::endl;

    std::vector<uint8_t> buf(line.begin(), line.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

void SMTPSession::reply_code(int code, std::string_view msg) {
    reply(std::to_string(code) + " " + std::string(msg));
}

void SMTPSession::reply_multiline(
    int code, const std::vector<std::string>& lines
) {
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

    std::cout << "[smtp:" << conn_id_ << "] > " << code_str << " (multiline, " << lines.size() << " lines)\n";

    std::vector<uint8_t> buf(out.begin(), out.end());
    loop_.submit_write(conn_id_, std::move(buf));
}

std::string_view SMTPSession::trim(std::string_view sv) {
    auto start = sv.find_first_not_of(" \t\r\n");
    
    if (start == std::string_view::npos) {
        return{};
    }

    auto end = sv.find_last_not_of(" \t\r\n");
    return sv.substr(start, end - start + 1);
}

std::string_view SMTPSession::extract_address(std::string_view arg) {
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
