#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <span>

class IoUringLoop;

enum class SMTPState {
    Connected,
    Greeted,
    Mail,
    RCPT,
    Data,
    Done,
};

struct Envelope {
    std::string mail_from;
    std::vector<std::string> rcpt_to;
    std::string body;
};

class SMTPSession {
    public:
        SMTPSession(
            uint64_t conn_id,
            std::string remote_ip,
            IoUringLoop& loop
        );

        void on_data(std::span<const uint8_t> bytes);

    private:
        void process_line(std::string_view line);

        void cmd_ehlo(std::string_view arg);
        void cmd_helo(std::string_view arg);
        void cmd_mail(std::string_view arg);
        void cmd_rcpt(std::string_view arg);
        void cmd_data();
        void cmd_rset();
        void cmd_noop();
        void cmd_quit();
        void cmd_starttls();

        void accumulate_data(std::string_view line);

        void reply(std::string_view text);
        void reply_code(int code, std::string_view msg);
        void reply_multiline(int code, const std::vector<std::string>& lines);

        bool deliver();

        static std::string_view trim(std::string_view sv);
        static std::string_view extract_address(std::string_view arg);

        uint64_t conn_id_;
        std::string remote_ip_;
        IoUringLoop& loop_;

        SMTPState state_{SMTPState::Connected};
        std::string line_buf;
        Envelope env_;
        std::string client_helo_;

        std::string data_tail_;

};
