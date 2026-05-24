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

}

void SubmissionServer::process_line(std::string_view line) {

}

void SubmissionServer::cmd_ehlo(std::string_view arg) {

}

void SubmissionServer::cmd_starttls() {

}

void SubmissionServer::accumulate_data(std::string_view line)
{
}

void SubmissionServer::cmd_auth(std::string_view arg) {

}

void SubmissionServer::cmd_helo(std::string_view arg) {

}

void SubmissionServer::cmd_mail(std::string_view arg) {

}

void SubmissionServer::cmd_rcpt(std::string_view arg) {

}

void SubmissionServer::cmd_data() {

}

void SubmissionServer::cmd_rset() {

}

void SubmissionServer::cmd_noop() {

}

void SubmissionServer::cmd_quit() {

}

bool SubmissionServer::deliver() {

}

void SubmissionServer::reply(int code, std::string_view text)
{
}

void SubmissionServer::reply_multiline(int code, const std::vector<std::string> &lines)
{
}

std::string_view SubmissionServer::trim(std::string_view sv) {

}

std::string_view SubmissionServer::extract_address(std::string_view arg) {
    
}
