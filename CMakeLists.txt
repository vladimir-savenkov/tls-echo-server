cmake_minimum_required(VERSION 3.16)
project(tls_echo_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# compile_commands.json для clangd/clang-tidy (см. пункт CI про статический анализ)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Выявляем устаревшие API Asio, удалённые в новых версиях Boost.
add_compile_definitions(BOOST_ASIO_NO_DEPRECATED)
if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
if(MSVC)
    # Исключения нужны также при переопределении CMAKE_CXX_FLAGS в CI.
    add_compile_options(/utf-8 /EHsc)
endif()

# Инструментация покрытия тестами (gcc/clang, см. scripts/coverage.sh)
option(ENABLE_COVERAGE "Enable code coverage instrumentation (gcov)" OFF)
if(ENABLE_COVERAGE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "ENABLE_COVERAGE requires GCC or Clang")
    endif()
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

# Поиск зависимостей
find_package(Boost REQUIRED COMPONENTS system thread program_options)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED) # Если ставишь через vcpkg/conan, иначе скачай header-only
find_package(Threads REQUIRED)

# Общая библиотека протокола
add_library(protocol src/protocol.cpp)
target_include_directories(protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Сетевое ядро: сервер и клиент в одной статической библиотеке, чтобы
# боевые бинарники и сквозной тест линковались с одним и тем же кодом
# (без дублирования списков исходников) и инкрементальная сборка не
# перекомпилировала исходники в каждой цели.
add_library(tls_core STATIC
    src/server.cpp
    src/client.cpp
)
target_link_libraries(tls_core PUBLIC
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    protocol
    Threads::Threads
)
target_include_directories(tls_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Сервер
add_executable(server src/main.cpp)
target_link_libraries(server PRIVATE
    tls_core
    Boost::thread
    Boost::program_options
)

# Клиент
add_executable(client src/main_client.cpp)
target_link_libraries(client PRIVATE
    tls_core
    Boost::thread
    Boost::program_options
)

enable_testing()
add_executable(test_packet tests/test_packet.cpp)
target_link_libraries(test_packet PRIVATE protocol)
add_test(NAME packet_tests COMMAND test_packet)

add_executable(test_client tests/test_client.cpp)
target_link_libraries(test_client PRIVATE protocol Boost::system)
add_test(NAME client_tests COMMAND test_client)

add_executable(test_client_integration tests/test_client_integration.cpp)
target_link_libraries(test_client_integration PRIVATE
    protocol
    Boost::system
    Threads::Threads
)
add_test(NAME client_integration_tests COMMAND test_client_integration)
set_tests_properties(client_integration_tests PROPERTIES TIMEOUT 30)

add_executable(test_log_payload tests/test_log_payload.cpp)
target_include_directories(test_log_payload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_test(NAME log_payload_tests COMMAND test_log_payload)

# Сквозной тест: реальный TlsServer и TlsClient через TLS на loopback
add_executable(test_tls_end_to_end tests/test_tls_end_to_end.cpp)
target_link_libraries(test_tls_end_to_end PRIVATE tls_core)
add_test(NAME tls_end_to_end_tests COMMAND test_tls_end_to_end)
set_tests_properties(tls_end_to_end_tests PROPERTIES TIMEOUT 30)

install(TARGETS server client RUNTIME DESTINATION bin)
install(PROGRAMS
    scripts/interactive_client.py
    scripts/multi_client_test.py
    scripts/generate-certs.sh
    DESTINATION bin
)
install(FILES README.md LICENSE DESTINATION share/tls-echo-server)
