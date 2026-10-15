# TLS Echo Server

Асинхронный TLS-сервер на C++17 с бинарным протоколом, CRC32 и пулами объектов.
Проект демонстрирует понимание сетевого программирования, криптографии, управления памятью и безопасности.

## Особенности

- **Протокол:** Бинарный формат пакета (Header: ID, Len, CRC + Payload).
- **Безопасность:** TLS 1.2/1.3 (OpenSSL), проверка целостности данных (CRC32).
- **Производительность:** Асинхронность (Boost.Asio), пул объектов (Object Pool), асинхронный логгер (spdlog).
- **Память:** Строгое соблюдение RAII, отсутствие утечек, выравнивание структур.
- **Тестируемость:** Архитектура готова для внедрения моков (Dependency Injection).

## Технологии

- C++17
- Boost.Asio + Boost.Beast
- OpenSSL
- spdlog
- CMake

## Как запустить

1. Сгенерируйте сертификаты:
   ```bash
   cd scripts
   chmod +x generate_certs.sh
   ./generate_certs.sh
   ```

## Python-утилиты

Параллельная проверка нескольких TLS-соединений:

```bash
python3 scripts/multi_client_test.py --host localhost --port 8443 \
  --clients 10 --messages 5 --insecure
```

Интерактивный клиент:

```bash
python3 scripts/interactive_client.py --host localhost --port 8443 --insecure
```

`--insecure` предназначен только для локальной проверки. Для проверки
сертификата передайте CA или самоподписанный сертификат сервера:

```bash
python3 scripts/interactive_client.py --ca-cert path/to/server.crt
```
