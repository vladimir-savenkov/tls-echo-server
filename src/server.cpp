#include "server.h"
#include "protocol.h"
#include <iostream>
#include <algorithm>

// ============================================================================
// TlsServer Implementation
// ============================================================================

TlsServer::TlsServer(boost::asio::io_context& io_context,
                    boost::asio::ssl::context& ssl_context,
                    unsigned short port,
                    std::shared_ptr<spdlog::logger> logger)
    : acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      ssl_context_(ssl_context),
      logger_(logger) {

    logger_->info("Server starting on port {}", port);
    do_accept();
}

TlsServer::~TlsServer() {
    if (acceptor_.is_open()) {
        acceptor_.close();
        logger_->debug("Acceptor closed");
    }
}

void TlsServer::run() {
    logger_->info("Event loop started");
    acceptor_.get_executor().context().run();
}

void TlsServer::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec,
                                  boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket(socket, ssl_context_);

            auto session = std::make_shared<Session>(std::move(ssl_socket), logger_);
            session->start();
        } else {
            logger_->error("Accept error: {}", ec.message());
        }

        do_accept();
    });
}

// ============================================================================
// Session Implementation
// ============================================================================

TlsServer::Session::Session(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket,
                             std::shared_ptr<spdlog::logger> logger)
    : socket_(std::move(socket)), logger_(logger) {}

void TlsServer::Session::start() {
    socket_.async_handshake(boost::asio::ssl::stream_base::server,
        [self = shared_from_this()](boost::system::error_code ec) {
            if (!ec) {
                self->logger_->info("Client connected and TLS handshake successful");
                self->read_header();
            } else {
                self->logger_->error("Handshake failed: {}", ec.message());
            }
        });
}

void TlsServer::Session::read_header() {
    boost::asio::async_read(socket_,
        boost::asio::buffer(header_buf_, sizeof(PacketHeader)),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                PacketHeader hdr;
                std::memcpy(&hdr, self->header_buf_, sizeof(hdr));

                self->current_id_ = ntohl(hdr.id);
                self->expected_len_ = ntohs(hdr.len);
                self->expected_crc_ = ntohl(hdr.crc);

                self->logger_->trace("Received packet: ID={}, Len={}, CRC={}",
                               self->current_id_, self->expected_len_, self->expected_crc_);

                self->payload_buf_.resize(self->expected_len_);
                self->read_payload(self->expected_len_);
            } else {
                self->logger_->error("Read header failed: {}", ec.message());
            }
        });
}

void TlsServer::Session::read_payload(uint16_t len) {
    boost::asio::async_read(socket_,
        boost::asio::buffer(payload_buf_, len),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                uint32_t calc_crc = calculate_crc32(self->payload_buf_.data(), length);
                if (calc_crc != self->expected_crc_) {
                    self->logger_->error("CRC Mismatch! Packet corrupted. Expected: {}, Got: {}",
                                   self->expected_crc_, calc_crc);
                    return;
                }

                self->logger_->trace("CRC Check Passed. Payload size: {}", length);

                Packet response_pkt(self->current_id_, self->payload_buf_);
                self->write_response(response_pkt);
            } else {
                self->logger_->error("Read payload failed: {}", ec.message());
            }
        });
}

void TlsServer::Session::write_response(const Packet& pkt) {
    auto buffer = std::make_shared<std::vector<char>>(pkt.serialize());

    boost::asio::async_write(socket_,
        boost::asio::buffer(*buffer),
        [self = shared_from_this(), buffer](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                self->logger_->trace("Response sent successfully");
                self->read_header();
            } else {
                self->logger_->error("Write failed: {}", ec.message());
            }
        });
}
