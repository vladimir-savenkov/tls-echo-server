#include "client.h"
#include "protocol.h"
#include <iostream>
#include <algorithm>

TlsClient::TlsClient(boost::asio::io_context& io_context,
                    boost::asio::ssl::context& ssl_context,
                    const std::string& host,
                    unsigned short port,
                    std::shared_ptr<spdlog::logger> logger)
    : socket_(io_context, ssl_context),
      logger_(logger),
      host_(host),
      port_(port) {}

void TlsClient::start() {
    logger_->info("Connecting to {}:{}...", host_, port_);

    boost::asio::ip::tcp::resolver resolver(socket_.get_executor());
    auto endpoints = resolver.resolve(host_, std::to_string(port_));

    // Подключение к первой точке
    boost::asio::connect(socket_.lowest_layer(), endpoints);

    logger_->info("Connected. Starting TLS handshake...");

    // TLS Handshake
    socket_.async_handshake(boost::asio::ssl::stream_base::client,
        [this](boost::system::error_code ec) {
            if (!ec) {
                logger_->info("TLS Handshake successful!");
                send_packets(5); // Отправляем 5 пакетов
            } else {
                logger_->error("TLS Handshake failed: {}", ec.message());
            }
        });
}

void TlsClient::send_packets(int count) {
    for (int i = 0; i < count; ++i) {
        std::string payload = "Hello from C++ Client, packet #" + std::to_string(i);

        // Формируем пакет
        Packet pkt(100 + i, payload);
        auto buffer = pkt.serialize();

        logger_->trace("Sending packet #{}, size: {} bytes", i, buffer.size());

        // Асинхронная запись
        boost::asio::async_write(socket_, boost::asio::buffer(buffer),
            [this, i](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    logger_->trace("Packet #{} sent successfully", i);
                    packets_sent_++;
                    // После отправки каждого пакета можно сразу читать ответ,
                    // но для простоты мы запустим цикл чтения отдельно или после отправки всех.
                    // Здесь мы просто продолжаем логику.
                } else {
                    logger_->error("Failed to send packet #{}: {}", i, ec.message());
                }
            });
    }

    // Запускаем чтение ответов.
    // В реальном протоколе лучше читать ответ сразу после отправки каждого пакета (Request/Response),
    // но для демонстрации цикла чтения сделаем отдельный вызов.
    // Чтобы синхронизировать, проще сделать последовательную отправку с ожиданием ответа.
    // Перепишем логику чуть проще для надежности: Send -> Wait Response -> Send...

    // Сброс счетчика и запуск правильного цикла (Send-Wait-Read)
    packets_sent_ = 0;
    packets_received_ = 0;
    read_response();
}

// Исправленная логика: Send one, Read one
void TlsClient::read_response() {
    if (packets_sent_ >= 5) {
        logger_->info("All packets sent and processed. Total sent: {}, received: {}", packets_sent_, packets_received_);
        return;
    }

    // 1. Читаем заголовок ответа
    boost::asio::async_read(socket_, boost::asio::buffer(header_buf_, sizeof(PacketHeader)),
        [this](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                PacketHeader hdr;
                std::memcpy(&hdr, header_buf_, sizeof(hdr));

                uint32_t id = ntohl(hdr.id);
                uint16_t len = ntohs(hdr.len);
                uint32_t crc = ntohl(hdr.crc);

                logger_->trace("Received header: ID={}, Len={}, CRC={}", id, len, crc);

                // 2. Читаем тело
                payload_buf_.resize(len);
                boost::asio::async_read(socket_, boost::asio::buffer(payload_buf_),
                    [this, id, len, crc](boost::system::error_code ec, std::size_t length) {
                        if (!ec) {
                            // 3. Проверка CRC
                            uint32_t calc_crc = calculate_crc32(payload_buf_.data(), length);
                            if (calc_crc != crc) {
                                logger_->error("CRC Mismatch! Expected: {}, Got: {}", crc, calc_crc);
                                return;
                            }

                            logger_->info("Packet #{} received OK. Data: {}", packets_received_, payload_buf_);
                            packets_received_++;

                            // 4. Отправляем следующий пакет (цикл)
                            packets_sent_++;

                            if (packets_sent_ < 5) {
                                std::string next_payload = "Hello from C++ Client, packet #" + std::to_string(packets_sent_);
                                Packet next_pkt(100 + packets_sent_, next_payload);
                                auto buffer = next_pkt.serialize();

                                logger_->trace("Sending next packet #{}...", packets_sent_);
                                boost::asio::async_write(socket_, boost::asio::buffer(buffer),
                                    [this](boost::system::error_code ec, std::size_t) {
                                        if (!ec) {
                                            read_response(); // Рекурсивный вызов для чтения ответа на новый пакет
                                        } else {
                                            logger_->error("Failed to send packet #{}: {}", packets_sent_, ec.message());
                                        }
                                    });
                            } else {
                                logger_->info("Test sequence completed.");
                                // Закрытие соединения
                                socket_.lowest_layer().close();
                            }
                        } else {
                            logger_->error("Failed to read payload: {}", ec.message());
                        }
                    });
            } else {
                logger_->error("Failed to read header: {}", ec.message());
            }
        });
}

