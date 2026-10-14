cmake_minimum_required(VERSION 3.16)
project(tls_echo_server VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Поиск зависимостей
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED) # Если ставишь через vcpkg/conan, иначе скачай header-only

# Исходники
add_executable(server src/main.cpp src/server.cpp)
target_link_libraries(server PRIVATE Boost::system Boost::thread OpenSSL::SSL OpenSSL::Crypto spdlog::spdlog)

# Тесты (заглушка пока)
enable_testing()
add_executable(test_server tests/test_main.cpp)
target_link_libraries(test_server PRIVATE server)
