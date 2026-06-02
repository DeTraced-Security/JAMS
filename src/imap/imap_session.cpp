#include "imap_session.hpp"
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

IMAPSession::IMAPSession(
    uint64_t conn_id, std::string remote_ip, IoUringLoop& loop,
    Auth::CredentialStore& cred_store, const std::string& mail_root
) : conn_id_(conn_id), remote_ip_(remote_ip), loop_(loop), cred_store_(cred_store),
    mail_root_(mail_root) {
        // Send greeting on connect
        untagged("OK [CAPABILITY IMAPrev4 STARTTLS AUTH=PLAIN IDLE] JAMS IMAP server ready");
    }

void IMAPSession::on_data(std::span<const uint8_t> bytes) {
    for (uint8_t b : bytes) {
        if (b == '\n') {
            if (!line_buf_.empty() && line_buf_.back() == '\r') {
                line_buf_.pop_back();
            }

            process_line(line_buf_);
            line_buf_.clear();
        } else {
            line_buf_ += static_cast<char>(b);

            if (line_buf_.size() > 8192) {
                bad("*", "Line too long");
                line_buf_.clear();
            }
        }
    }
}

void IMAPSession::process_line(const std::string& line) {
    if (line.empty()) {
        return;
    }

    std::cout << "[IMAP] " << conn_id_ << " " << line << std::endl;

    std::istringstream ss(line);
    std::string tag, command;
    ss >> tag >> command;

    std::string args;
    std::getline(ss, args);

    if (!args.empty() && args.front() == ' ') {
        args.erase(0, 1);
    }

    // normalise command to UPPERCASE
    std::transform(command.begin(), command.end(), command.begin(), ::toupper);

    if (command == "CAPABILITY") {
        cmd_capability(tag);
        return;
    }

    if (command == "NOOP") {
        cmd_noop(tag);
        return;
    }

    if (command == "LOGOUT") {
        cmd_logout(tag);
        return;
    }

    if (state_ == State::NotAuthenticated) {
        if (command == "STARTTLS") {
            cmd_starttls(tag);
            return;
        }

        if (command == "LOGIN") {
            cmd_login(tag, args);
            return;
        }

        if (command == "AUTHENTICATE") {
            no(tag, "Use LOGIN or STARTTLS");
            return;
        }

        no(tag, "Not authenticated");
        return;
    }

    /// Commands available once Authenticated to move into the Selected state
    if (state_ == State::Authenticated || state_ == State::Selected) {
        if (command == "SELECT") {
            cmd_select(tag, args, false);
            return;
        }

        if (command == "EXAMINE") {
            cmd_select(tag, args, true);
        }

        if (command == "LIST") {
            cmd_list(tag, args);
            return;
        }

        if (command == "LSUB") {
            cmd_lsub(tag, args);
            return;
        }

        if (command == "STATUS") {
            cmd_status(tag, args);
            return;
        }
    }

    /// Commands only available to the Selected state, after AUTH
    if (state_ == State::Selected) {
        if (command == "FETCH") { 
            cmd_fetch(tag, args); 
            return; 
        }

        if (command == "STORE") { 
            cmd_store(tag, args); 
            return; 
        }
        
        if (command == "EXPUNGE") { 
            cmd_expunge(tag);
            return; 
        }
        
        if (command == "CHECK") { 
            cmd_check(tag);
            return; 
        }

        if (command == "CLOSE") { 
            cmd_close(tag);
            return; 
        }
    }

    bad(tag, "Command not recognised in current state");
}

void IMAPSession::cmd_capability(const std::string& tag) {
    untagged("CAPABILITY IMAPrev4 STARTTLS AUTH=PLAIN LITERAL+ SASL-IR");

    ok(tag, "CAPABILITY completed");
}

void IMAPSession::cmd_noop(const std::string& tag) {
    if (state_ == State::Selected) {
        incorporate_new();
    }

    ok(tag, "NOOP completed");
}

void IMAPSession::cmd_logout(const std::string& tag) {
    untagged("BYE JAMS IMAP server logging out");
    ok(tag, "LOGOUT completed");

    state_ = State::Logout;
    loop_.submit_close(conn_id_);
}

void IMAPSession::cmd_starttls(const std::string& tag) {
    ok(tag, "Begin TLS negotiation");

    loop_.upgrade_tls(conn_id_);
}

void IMAPSession::cmd_login(const std::string& tag, const std::string& args) {
    std::istringstream ss(args);
    std::string user, pass;

    // Simpel unquoted parse, literal parsing not yet supported
    auto read_token = [](std::istringstream& s) {
        std::string token;
        s >> token;

        if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }

        return token;
    };

    user = read_token(ss);
    pass = read_token(ss);

    if (user.empty() || pass.empty()) {
        bad(tag, "LOGIN requres username and password");
        return;
    }

    if (!cred_store_.verify(user, pass)) {
        no(tag, "[AUTHENTICATIONFAILED] Invalid credentials");
        return;
    }

    username_ = user;
    state_ = State::Authenticated;
    
    std::cout << "[IMAP] " << conn_id_ << " authenticated: " << username_ << std::endl;

    ok(tag, "[CAPABILITY IMAP4rev1] LOGIN completed");
}

void IMAPSession::cmd_select(
    const std::string& tag, const std::string& mailbox, 
    bool read_only
) {
    // Strip quotes from mailbox name
    std::string mbox = mailbox;
    if (mbox.size() >= 2 && mbox.front() == '"' && mbox.back() == '"') {
        mbox = mbox.substr(1, mbox.size() - 2);
    }

    if (mbox.empty()) {
        bad(tag, "SELECT requires a mailbox name");
        return;
    }

    // normalise inbox to UPPERCASE
    std::string u_mbox = mbox;
    std::transform(u_mbox.begin(), u_mbox.end(), u_mbox.begin(), ::toupper);

    if (u_mbox == "INBOX") {
        mbox = "INBOX";
    }

    load_mailbox(mbox);

    selected_mailbox_ = mbox;
    read_only_ = read_only;
    state_ = State::Selected;

    // Require untagged responses
    untagged(std::to_string(messages_.size()) + " EXISTS");
    untagged("0 RECENT");
    untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
    untagged("OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Permanent flags");
    untagged("OK [UIDVALIDITY " + std::to_string(IMAP_UUID_VALIDITY) + "] UIDs valid");
    untagged("OK [UIDNEXT " + std::to_string(next_uuid_) + "] Next UID");

    if (read_only) {
        ok(tag, "[READ-ONLY] EXAMINE completed");
    } else {
        ok(tag, "[READ-WRITE] SELECT completed");
    }
}


void IMAPSession::cmd_list(const std::string& tag, const std::string& /* args */) {
    // Minimal LIST, beta will extend off this
    untagged("LIST (\\HasNoChildren) \"/\" \"INBOX\"");
    ok(tag, "LIST completed");   
}

void IMAPSession::cmd_lsub(const std::string& tag, const std::string& /* args */) {
    // Likewise with cmd_list, beta will extend this
    untagged("LSUB () \"/\" \"INBOX\"");
    ok(tag, "LSUB completed");
}

void IMAPSession::cmd_status(const std::string& tag, const std::string& args) {
    // STATUS will show the messages unseen
    std::istringstream ss(args);
    std::string mbox, items_str;

    ss >> mbox;
    std::getline(ss, items_str);

    size_t unseen = 0;

    for (const auto& message : messages_) {
        if (message.flags.find("\\Seen") == std::string::npos) {
            ++unseen;
        }
    }

    std::string response = "STATUS " + mbox + " (MESSAGES "
        + std::to_string(messages_.size())
        + " UNSEEN " + std::to_string(unseen)
        + " UIDNEXT " + std::to_string(next_uuid_) + ")";

    untagged(response);
    ok(tag, "STATUS completed");
}

void IMAPSession::cmd_fetch(const std::string& tag, const std::string& args) {
    // fetch teh sequence-set items:
    auto sp = args.find(' ');
    if (sp == std::string::npos) {
        bad(tag, "FETCH requires sequence-set and items");
        return;
    }

    std::string seq_str = args.substr(0, sp);
    std::string items = args.substr(sp + 1);

    auto seqs = parse_sequence_set(seq_str);

    for (uint32_t seq : seqs) {
        // Find the message by the sequence number
        auto itr = std::find_if(messages_.begin(), messages_.end(), [seq](const MessageMeta& m) {
            return m.seq == seq;
        });

        if (itr == messages_.end()) {
            // No messages to iterate over
            continue;
        }

        std::string response = fetch_message(*itr, items);
        untagged(response);

        // if BODY[] was fetched without .PEEK, set it as seen
        std::string upper_items = items;
        std::transform(upper_items.begin(), upper_items.end(), upper_items.begin(), ::toupper);

        if (
            upper_items.find("BODY[") != std::string::npos &&
            upper_items.find(".PEEK") == std::string::npos &&
            !read_only_
        ) {
            if (itr->flags.find("\\Seen") == std::string::npos) {
                itr->flags += " \\Seen";
            }
        }
    }
    
    ok(tag, "FETCH completed");
}

std::string IMAPSession::fetch_message(
    const MessageMeta& msg, const std::string& items
) const {
    std::string upper = items;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    std::string result = std::to_string(msg.seq) + " FETCH (";
    bool first = true;

    auto add = [&](const std::string& part) {
        if (!first) {
            result += ' ';
        }

        result += part;
        first = false;
    };

    if (upper.find("FLAGS") != std::string::npos) {
        add("FLAGS " + msg.flags + ")");
    }

    if (upper.find("UID") != std::string::npos) {
        add("UID " + std::to_string(msg.uuid) + ")");
    }

    if (upper.find("RFC822.SIZE") != std::string::npos) {
        add("RFC822.SIZE " + std::to_string(msg.size));
    }

    if (upper.find("ENVELOPE") != std::string::npos) {
        add("ENVELOPE " + build_envelope(msg));
    }

    if (upper.find("BODYSTRUCTURE") != std::string::npos) {
        add("BODYSTRUCTURE " + build_body(msg));
    }

    if (
        upper.find("BODY[") != std::string::npos ||
        upper.find("RFC822") != std::string::npos
    ) {
        auto blob = read_blob(msg);
        add(
            "BODY{} {" + std::to_string(blob.size()) + "}\r\n" + 
            std::string(blob.begin(), blob.end())
        );
    }

    result += ')';
    return result;
}

std::vector<uint8_t> IMAPSession::read_blob(const MessageMeta& msg) const {
    std::string dir = msg.in_cur ? "/cur/" : "/new/";
    std::string path = mail_root_ + "/" + username_ + dir + msg.filename;

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "[IMAP] failed to open path: " << path << std::endl;
        return {};
    }

    return std::vector<uint8_t>(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

std::string IMAPSession::build_envelope(const MessageMeta& /* msg */) const {
    // Synthetic headers to so clients can display something before decryption
    return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";
}

std::string IMAPSession::build_body(const MessageMeta& msg) const {
    return "(\"APPLICATION\" \"OCTET-STREAM\" "
        "(\"X-JAMS-Encrypted\" \"AES-256-GCM\") NIL NIL \"BASE64\" "
        + std::to_string(msg.size) + " NIL NIL NIL)";
}

void IMAPSession::cmd_store(const std::string& tag, const std::string& args) {
    if (read_only_) {
        no(tag, "[READ-ONLY] Mailbox is read-only");
        return;
    }

    // STORE seq FLAGS are \Seen, \Deleted, etc.
    std::istringstream ss(args);
    std::string seq_str, action, flags_str;

    ss >> seq_str >> action;
    std::getline(ss, flags_str);

    // trim and strip parenthesis
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t(");
        size_t b = s.find_last_not_of(" \t)");

        return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
    };

    flags_str = trim(flags_str);

    // Normalise the action to UPPERCASE
    std::string upper = action;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

    auto seqs = parse_sequence_set(seq_str);

    for (uint32_t seq : seqs) {
        auto itr = std::find_if(
            messages_.begin(), messages_.end(), 
            [seq](const MessageMeta& m) {
                return m.seq == seq;
        });

        if (itr == messages_.end()) {
            continue;
        }

        if (upper == "FLAGS" || upper == "FLAGS.SILENT") {
            itr->flags = flags_str;
        } else if (upper == "+FLAGS" || upper == "+FLAGS.SILENT") {
            if (itr->flags.find(flags_str) == std::string::npos) {
                itr->flags += (itr->flags.empty() ? "" : " ") + flags_str;
            }
        } else if (upper == "-FLAGS" || upper == "-FLAGS.SILENT") {
            size_t pos = itr->flags.find(flags_str);
            if (pos != std::string::npos) {
                itr->flags.erase(pos, flags_str.size());
            }
        }

        // Send FETCH unless .SILENT is present
        if (upper.find(".SILENT") == std::string::npos) {
            untagged(std::to_string(seq) + " FETCH (FLAGS (" + itr->flags + "))");
        }
    }

    ok(tag, "STORE completed");
}

void IMAPSession::cmd_expunge(const std::string& tag) {
    if (read_only_) {
        no(tag, "[READ-ONLY] Mailbox is read-only");
        return;
    }

    std::vector<MessageMeta> remaining;
    uint32_t seq = 0;

    for (auto& msg : messages_) {
        ++seq;

        if (msg.flags.find("\\Deleted") != std::string::npos) {
            // Delete the file!
            std::string dir = msg.in_cur ? "/cur/" : "/new/";
            std::string path = mail_root_ + username_ + dir + msg.filename;

            ::unlink(path.c_str());
            untagged(std::to_string(seq) + " EXPUNGE");
            --seq;
        } else {
            remaining.push_back(std::move(msg));
        }
    }

    messages_ = std::move(remaining);

    // Reassign sequences
    for (uint32_t i = 0; i < messages_.size(); ++i) {
        messages_[i].seq = i + 1;
    }

    ok(tag, "EXPUNGE completed");
}

void IMAPSession::cmd_check(const std::string& tag) {
    incorporate_new();
    ok(tag, "CHECK completed");
}

void IMAPSession::cmd_close(const std::string& tag) {
    // Silently expunge \Deleted messages
    if (!read_only_) {
        for (auto& msg : messages_) {
            if (msg.flags.find("\\Deleted") != std::string::npos) {
                std::string dir = msg.in_cur ? "/cur/" : "/new/";
                std::string path = mail_root_ + username_ + dir + msg.filename;

                ::unlink(path.c_str());
            }
        }
    }

    messages_.clear();
    selected_mailbox_.clear();
    state_ = State::Authenticated;

    ok(tag, "CLOSE completed");
}

void IMAPSession::load_mailbox(const std::string& mailbox) {
    messages_.clear();
    next_uuid_ = 1;

    std::string base = mail_root_ + "/" + username_;
    if (mailbox != "INBOX") {
        // Subfolders are as per Maildir++ convention:
        // .FolderName
        base += "/." + mailbox;
    }

    uint32_t seq = 0;
    
    for (const char* subdir : {"cur", "new"}) {
        bool is_cur = (std::string(subdir) == "cur");
        std::string dir = base + "/" + subdir;

        DIR* d = ::opendir(dir.c_str());
        if (!d) {
            // No directory exists, we can soft-fail
            continue;
        }

        struct dirent* ent;
        while ((ent = ::readdir(d)) != nullptr) {
            if (ent->d_name[0] == '.') {
                continue;
            }

            std::string fname = ent->d_name;

            // Get the file size
            struct stat st{};
            std::string full = dir + "/" + fname;

            if (::stat(full.c_str(), &st) != 0) {
                continue;
            }

            MessageMeta meta;
            meta.uuid = uuid_from_file(fname);
            meta.seq = ++seq;
            meta.filename = fname;
            meta.flags = flags_from_file(fname);
            meta.size = static_cast<size_t>(st.st_size);
            meta.in_cur = is_cur;

            messages_.push_back(std::move(meta));
        }

        ::closedir(d);
    }

    // Sort by UUID for stable ordering
    std::sort(
        messages_.begin(), messages_.end(), 
        [](const MessageMeta& a, const MessageMeta& b) {
            return a.uuid < b.uuid;
    });

    // reassign sequences after sort
    for (uint32_t i = 0; i < messages_.size(); i++) {
        messages_[i].seq = i + 1;
        next_uuid_ = std::max(next_uuid_, messages_[i].uuid + 1);
    }

    std::cout << "[IMAP] " << conn_id_ << " loaded " << messages_.size() 
        << " messages from " << mailbox << std::endl;
}

size_t IMAPSession::scan_new() const {
    std::string dir = mail_root_ + "/" + username_ + "/new";
    size_t count{0};

    DIR* d = ::opendir(dir.c_str());
    if (!d) {
        return count;
    }

    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] != '.') {
            ++count;
        }
    }

    ::closedir(d);
    return count;
}

void IMAPSession::incorporate_new() {
    std::string new_dir = mail_root_ + "/" + username_ + "/new";
    std::string cur_dir = mail_root_ + "/" + username_ + "/cur";

    DIR* d = ::opendir(new_dir.c_str());
    if (!d) {
        return;
    }

    struct dirent* ent;
    while ((ent = ::readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') {
            continue;
        }

        std::string fname = ent->d_name;
        std::string src = new_dir + "/" + fname;

        // Add :2, flags if not present
        std::string dst_name = fname;
        if (dst_name.find(":2,") == std::string::npos) {
            dst_name += ":2,";
        }

        std::string dst = cur_dir + "/" + dst_name;

        if (::rename(src.c_str(), dst.c_str()) == 0) {
            struct stat st{};

            if (::stat(dst.c_str(), &st) == 0) {
                MessageMeta meta;
                meta.uuid = uuid_from_file(dst_name);
                meta.seq = static_cast<uint32_t>(messages_.size()) + 1;
                meta.filename = dst_name;
                meta.size = static_cast<size_t>(st.st_size);
                meta.in_cur = true;
                meta.flags = "";

                messages_.push_back(std::move(meta));
                next_uuid_ = std::max(next_uuid_, meta.uuid + 1);
            }
        }
    }

    ::closedir(d);
}

uint32_t IMAPSession::uuid_from_file(const std::string& filename) {
    // Maildir conventions start with a UNIX timestamp, PID, then host
    // We'll be using the timestamp as the UUID
    auto dot = filename.find_first_of('.');
    if (dot == std::string::npos) {
        return 1;
    }

    uint32_t uuid = 0;
    auto [ptr, ec] = std::from_chars(filename.data(), filename.data() + dot, uuid);

    return (ec == std::errc{}) ? uuid : 1;
}

std::string IMAPSession::flags_from_file(const std::string& filename) {
    // Flags are placed after the :2,
    auto pos = filename.find(":2,");
    if (pos == std::string::npos) {
        return "";
    }

    std::string raw_flags = filename.substr(pos + 3);
    std::string imap_flags;

    if (raw_flags.find('D') != std::string::npos) {
        imap_flags += "\\Draft ";
    }

    if (raw_flags.find('F') != std::string::npos) {
        imap_flags += "\\Flagged ";
    }
    
    if (raw_flags.find('R') != std::string::npos) {
        imap_flags += "\\Answered ";
    }
    
    if (raw_flags.find('S') != std::string::npos) {
        imap_flags += "\\Seen ";
    
    }
    
    if (raw_flags.find('T') != std::string::npos) {
        imap_flags += "\\Deleted ";
    }

    if (!imap_flags.empty() && imap_flags.back() == ' ') {
        imap_flags.pop_back();
    }

    return imap_flags;
}

std::vector<uint32_t> IMAPSession::parse_sequence_set(
    const std::string& set
) const {
    std::vector<uint32_t> result;
    uint32_t max_seq = static_cast<uint32_t>(messages_.size());

    if (max_seq == 0) {
        return result;
    }

    // Split on ','
    std::istringstream ss(set);
    std::string range;

    while (std::getline(ss, range, ',')) {
        auto colon = range.find(':');

        auto parse_num = [&](const std::string& s) -> uint32_t {
            if (s == "*") {
                return max_seq;
            }
            
            uint32_t n = 0;
            std::from_chars(s.data(), s.data() + s.size(), n);
            
            return std::min(n, max_seq);
        };

        if (colon == std::string::npos) {
            uint32_t n = parse_num(range);

            if (n >= 1 && n <= max_seq) {
                result.push_back(n);
            }
        } else {
            uint32_t lo = parse_num(range.substr(0, colon));
            uint32_t hi = parse_num(range.substr(colon + 1));

            if (lo > hi) {
                std::swap(lo, hi);
            }

            for (uint32_t i = lo; i <= hi; ++i) {
                if (i >= 1 && i <= max_seq) {
                    result.push_back(i);
                }
            }
        }
    }

    return result;
}

void IMAPSession::send(const std::string& line) {
    std::cout << "[IMAP] " << conn_id_ << " > " << line << std::endl;
    std::string out = line + "\r\n";

    loop_.submit_write(conn_id_, std::vector<uint8_t>(out.begin(), out.end()));
}

void IMAPSession::ok(const std::string& tag, const std::string& msg) {
    send(tag + " OK " + msg);
}

void IMAPSession::no(const std::string& tag, const std::string& msg) {
    send(tag + " NO " + msg);
}

void IMAPSession::bad(const std::string& tag, const std::string& msg) {
    send(tag + " BAD " + msg);
}

void IMAPSession::untagged(const std::string& data) {
    send("* " + data);
}
