#pragma once

#include <boost/asio.hpp>
#include <chrono>
#include <cstdint>
#include <utility>

// Все методы вызываются на одном strand. Поколение защищает от уже готового
// обработчика таймера предыдущей операции после cancel().
class OperationDeadline {
public:
    // Параметр — const-ссылка: конструктор steady_timer принимает executor
    // только по const& и копирует его внутрь, перемещение невозможно по API Asio.
    explicit OperationDeadline(const boost::asio::any_io_executor& executor) : timer_(executor) {}

    template <typename Handler>
    void arm(std::chrono::milliseconds timeout, Handler handler) {
        const auto generation = ++generation_;
        expired_ = false;
        timer_.expires_after(timeout);
        timer_.async_wait([this, generation, handler = std::move(handler)](
                             boost::system::error_code error) mutable {
            if (!error && generation == generation_) {
                expired_ = true;
                handler();
            }
        });
    }

    void cancel() {
        ++generation_;
        timer_.cancel();
    }
    bool expired() const { return expired_; }

private:
    boost::asio::steady_timer timer_;
    uint64_t generation_ = 0;
    bool expired_ = false;
};
