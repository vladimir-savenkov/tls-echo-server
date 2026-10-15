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
        [this](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                PacketHeader hdr;
                std::memcpy(&hdr, header_buf_, sizeof(hdr));

                current_id_ = ntohl(hdr.id);
                expected_len_ = ntohs(hdr.len);
                expected_crc_ = ntohl(hdr.crc);

                logger_->trace("Received packet: ID={}, Len={}, CRC={}",
                               current_id_, expected_len_, expected_crc_);

                if (expected_len_ > 10 * 1024 * 1024) {
                    logger_->warn("DoS attempt detected: too large payload ({} bytes)", expected_len_);
                    return;
                }

                payload_buf_.resize(expected_len_);
                read_payload(expected_len_);
            } else {
                logger_->error("Read header failed: {}", ec.message());
            }
        });
}

void TlsServer::Session::read_payload(uint16_t len) {
    boost::asio::async_read(socket_,
        boost::asio::buffer(payload_buf_, len),
        [this](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                uint32_t calc_crc = calculate_crc32(payload_buf_.data(), length);
                if (calc_crc != expected_crc_) {
                    logger_->error("CRC Mismatch! Packet corrupted. Expected: {}, Got: {}",
                                   expected_crc_, calc_crc);
                    return;
                }

                logger_->trace("CRC Check Passed. Payload size: {}", length);

                Packet response_pkt(current_id_, payload_buf_);
                write_response(response_pkt);
            } else {
                logger_->error("Read payload failed: {}", ec.message());
            }
        });
}

void TlsServer::Session::write_response(const Packet& pkt) {
    auto buffer = pkt.serialize();

    boost::asio::async_write(socket_,
        boost::asio::buffer(buffer),
        [this, buffer = std::move(buffer)](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                logger_->trace("Response sent successfully");
                read_header(); // Next packet
            } else {
                logger_->error("Write failed: {}", ec.message());
            }
        });
}

