#pragma once

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <string>
#include <string_view>

// Общая настройка логгера сервера и клиента: асинхронная очередь
// (overrun_oldest — сетевые потоки не блокируются на журналирование),
// файл (усекается или дополняется) + цветной stdout, flush на warn и выше.
inline std::shared_ptr<spdlog::logger> make_logger(const std::string& name,
                                                   const std::string& file,
                                                   bool append) {
    spdlog::init_thread_pool(8192, 1);
    auto logger = spdlog::create_async_nb<spdlog::sinks::basic_file_sink_mt>(
        name, file, !append);
    logger->sinks().push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");
    logger->flush_on(spdlog::level::warn);
    return logger;
}

// Уровень журнала из строки CLI; неизвестное значение — info с предупреждением.
inline spdlog::level::level_enum log_level_from_string(std::string_view level,
                                                       spdlog::logger& logger) {
    if (level == "trace") return spdlog::level::trace;
    if (level == "debug") return spdlog::level::debug;
    if (level == "info") return spdlog::level::info;
    if (level == "warn") return spdlog::level::warn;
    if (level == "error") return spdlog::level::err;
    if (level == "critical") return spdlog::level::critical;
    logger.warn("Unknown log level '{}', using default 'info'", level);
    return spdlog::level::info;
}