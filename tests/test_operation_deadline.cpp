#include "operation_deadline.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <utility>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

// Прогоняет io_context не дольше duration: готовые обработчики и истёкшие
// таймеры отрабатывают; ожидание недоистёкших прерывается по лимиту.
// run_for() при возврате останавливает контекст (даже когда работа
// закончилась сама) — restart() обязателен перед каждым новым прогоном.
void run_for(boost::asio::io_context& io, std::chrono::milliseconds duration) {
    io.restart();
    io.run_for(duration);
}

// Истёкший дедлайн вызывает обработчик и переводит expired() в true.
void test_expired_deadline_calls_handler() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    bool handler_called = false;
    deadline.arm(std::chrono::milliseconds(1), [&handler_called] { handler_called = true; });
    run_for(io, std::chrono::milliseconds(500));
    check(handler_called, "expired deadline calls its handler");
    check(deadline.expired(), "expired() reports the fired deadline");
}

// cancel() до истечения: обработчик не вызывается, expired() остаётся false —
// транспортная ошибка после отмены не трактуется как таймаут.
void test_cancel_prevents_handler() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    bool handler_called = false;
    deadline.arm(std::chrono::milliseconds(60000), [&handler_called] { handler_called = true; });
    deadline.cancel();
    run_for(io, std::chrono::milliseconds(200));
    check(!handler_called, "cancelled deadline does not call its handler");
    check(!deadline.expired(), "cancelled deadline is not expired");
}

// Ключевой сценарий поколений: callback первого таймера уже в очереди
// io_context, затем операция отменяется и взводится новый дедлайн — ровно
// как TlsConnection делает end() -> begin(). Готовый callback старого
// поколения не должен вызывать обработчик и не должен взводить expired_:
// иначе следующая операция ошибочно трактовала бы свой сбой как таймаут.
void test_stale_callback_of_previous_generation_is_ignored() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    bool first_called = false;
    bool second_called = false;
    deadline.arm(std::chrono::milliseconds(0), [&first_called] { first_called = true; });
    // Очередь io_context ещё не прокручена: callback первого таймера готов.
    deadline.cancel();
    deadline.arm(std::chrono::milliseconds(50), [&second_called] { second_called = true; });
    run_for(io, std::chrono::milliseconds(500));
    check(!first_called, "stale callback of a cancelled deadline is ignored");
    check(second_called, "the freshly armed deadline still fires");
    check(deadline.expired(), "expired() reflects the current generation");
}

// После сработки дедлайна повторный arm() обязан сбросить expired():
// TlsConnection::end() читает expired() уже следующей операции.
void test_rearm_clears_expired_flag() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    bool first_called = false;
    bool second_called = false;
    deadline.arm(std::chrono::milliseconds(0), [&first_called] { first_called = true; });
    run_for(io, std::chrono::milliseconds(500));
    check(first_called && deadline.expired(), "deadline fires and reports expiry");
    deadline.arm(std::chrono::milliseconds(60000), [&second_called] { second_called = true; });
    check(!deadline.expired(), "re-arm clears the expired flag");
    deadline.cancel();
    run_for(io, std::chrono::milliseconds(200));
    check(!second_called && !deadline.expired(), "fresh generation protects the next operation");
}

// Цикл операций: часть истекает, часть отменяется до истечения. Защита
// поколений не должна «застрять» и блокировать новые дедлайны.
void test_interleaved_cancel_and_expiry() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    int fired = 0;
    for (int round = 0; round < 6; ++round) {
        deadline.arm(std::chrono::milliseconds(0), [&fired] { ++fired; });
        if (round % 2 == 0) {
            run_for(io, std::chrono::milliseconds(200));  // операция зависла: дедлайн истёк
        } else {
            deadline.cancel();  // операция успела завершиться до дедлайна
            run_for(io, std::chrono::milliseconds(200));
        }
    }
    check(fired == 3, "three of six deadlines fire across interleaved cancels");
}

// arm() принимает move-only обработчики: контракт Handler без std::function.
void test_accepts_move_only_handler() {
    boost::asio::io_context io;
    OperationDeadline deadline(io.get_executor());
    auto secret = std::make_unique<int>(7);
    int observed = 0;
    deadline.arm(std::chrono::milliseconds(0), [secret = std::move(secret), &observed] {
        observed = *secret;
    });
    run_for(io, std::chrono::milliseconds(500));
    check(observed == 7, "move-only handler is invoked");
}

}  // namespace

// Необработанное исключение обрушивает тест — это и есть сигнал провала.
int main() {  // NOLINT(bugprone-exception-escape)
    test_expired_deadline_calls_handler();
    test_cancel_prevents_handler();
    test_stale_callback_of_previous_generation_is_ignored();
    test_rearm_clears_expired_flag();
    test_interleaved_cancel_and_expiry();
    test_accepts_move_only_handler();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All operation deadline tests passed\n";
    return 0;
}
