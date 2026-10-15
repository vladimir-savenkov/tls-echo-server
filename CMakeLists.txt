cmake_minimum_required(VERSION 3.16)
project(tls_echo_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск зависимостей
find_package(Boost REQUIRED COMPONENTS system thread program_options)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED) # Если ставишь через vcpkg/conan, иначе скачай header-only
find_package(Threads REQUIRED)

# Общая библиотека протокола
add_library(protocol src/protocol.cpp)
target_include_directories(protocol PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Исходники
add_executable(server
    src/main.cpp
    src/server.cpp
)

target_link_libraries(server PRIVATE
    Boost::system
    Boost::thread
    Boost::program_options
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    protocol
    Threads::Threads
)


# Цель для клиента
add_executable(client
    src/main_client.cpp
    src/client.cpp
)

target_link_libraries(client PRIVATE
    Boost::system
    Boost::thread
    Boost::program_options
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
    protocol
    Threads::Threads
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
