#!/bin/bash
# Скрипт сборки Adler32 Checksum Validator

set -e

echo "=== Adler32 Checksum Validator Build Script ==="
echo ""

# Проверка наличия необходимых инструментов
check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "Ошибка: $1 не найден. Установите необходимые зависимости."
        exit 1
    fi
}

echo "Проверка зависимостей..."
check_command g++
check_command qmake
echo "Все зависимости найдены."
echo ""

# Сборка сервера
echo "=== Сборка сервера ==="
g++ -std=c++11 -pthread -O2 -o adler_server server.cpp
echo "Сервер собран: adler_server"
echo ""

# Сборка GUI клиента
echo "=== Сборка GUI клиента ==="
qmake adler_gui.pro
make clean 2>/dev/null || true
make -j$(nproc)
echo "GUI клиент собран: adler_gui"
echo ""

# Очистка временных файлов
echo "=== Очистка временных файлов ==="
rm -f *.o moc_*.cpp moc_*.o moc_predefs.h .qmake.stash Makefile
echo "Временные файлы удалены."
echo ""

echo "=== Сборка завершена ==="
echo ""
echo "Файлы для запуска:"
echo "  - adler_server  (сервер)"
echo "  - adler_gui     (GUI клиент)"
echo ""
echo "Для запуска сервера:"
echo "  ./adler_server 9999"
echo ""
echo "Для запуска клиента:"
echo "  ./adler_gui"
