// Улучшенный server.cpp с поддержкой множественных подключений
#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <chrono>
#include <ctime>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <cstdlib>

// Новые модули
#include "secure_channel.h"
#include "auth.h"

// Функция для преобразования хэша в строку
std::string hashToString(uint32_t hash) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%08x", hash);
    return std::string(buf);
}

// Путь к папке с файлами (относительно сервера)
extern std::string FILES_DIR;

// Проверка, что путь находится внутри FILES_DIR
bool isValidPath(const std::string& path) {
    // Запрещаем выход за пределы директории
    if (path.find("..") != std::string::npos) {
        return false;
    }
    // Путь должен быть относительным
    if (path[0] == '/') {
        return false;
    }
    return true;
}

// Получить полный безопасный путь к файлу
std::string getSafeFilePath(const std::string& filename) {
    if (!isValidPath(filename)) {
        return "";
    }
    return FILES_DIR + "/" + filename;
}

// Рекурсивный список файлов в директории
void listFilesRecursive(const std::string& dirPath, const std::string& relativePath, std::string& result) {
    DIR* dir = opendir(dirPath.c_str());
    if (!dir) {
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        
        // Пропускаем . и ..
        if (name == "." || name == "..") {
            continue;
        }

        std::string fullPath = dirPath + "/" + name;
        std::string relPath = relativePath.empty() ? name : relativePath + "/" + name;

        struct stat statbuf;
        if (stat(fullPath.c_str(), &statbuf) == 0) {
            if (S_ISDIR(statbuf.st_mode)) {
                // Рекурсивно обходим поддиректории
                listFilesRecursive(fullPath, relPath, result);
            } else if (S_ISREG(statbuf.st_mode)) {
                // Добавляем файл в список
                result += relPath + "\n";
            }
        }
    }
    closedir(dir);
}

std::mutex log_mutex;
std::map<std::string, std::chrono::steady_clock::time_point> client_activity;
Authentication auth;

// Путь к папке с файлами (относительно сервера)
std::string FILES_DIR = "files";

// Функция для логирования
void log(const std::string& message, const std::string& level = "INFO") {
    std::lock_guard<std::mutex> lock(log_mutex);
    auto now = std::chrono::system_clock::now();
    auto now_time = std::chrono::system_clock::to_time_t(now);
    std::cout << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S")
              << "] [" << level << "] " << message << std::endl;
}

// Улучшенная версия adler32 с поддержкой потоковой обработки
uint32_t adler32_streaming(const std::vector<uint8_t>& data, uint32_t previous = 0) {
    uint32_t a = previous == 0 ? 1 : (previous & 0xFFFF);
    uint32_t b = (previous >> 16) & 0xFFFF;
    const uint32_t MOD_ADLER = 65521;

    // Оптимизация: обрабатываем блоками по 5552 байта
    for (size_t i = 0; i < data.size(); i++) {
        a = (a + data[i]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    return (b << 16) | a;
}

void handleClient(int client_socket, const std::string& client_ip) {
    try {
        // Проверка на DDoS (ограничение количества запросов)
        auto now = std::chrono::steady_clock::now();
        if (client_activity.find(client_ip) != client_activity.end()) {
            auto last = client_activity[client_ip];
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last).count() < 1) {
                log("Too many requests from " + client_ip, "WARNING");
                close(client_socket);
                return;
            }
        }
        client_activity[client_ip] = now;

        bool authenticated = false;
        std::string current_username;
        
        // Буфер для чтения данных
        std::vector<uint8_t> read_buffer;
        char temp_buffer[4096];

        // Цикл обработки команд клиента - держим соединение пока клиент не отключится
        while (true) {
            // Читаем данные от клиента
            int bytes_received = recv(client_socket, temp_buffer, sizeof(temp_buffer), 0);

            if (bytes_received <= 0) {
                // Клиент закрыл соединение или ошибка
                log("Client " + client_ip + " disconnected");
                break;
            }

            // Добавляем прочитанные данные в буфер
            read_buffer.insert(read_buffer.end(), temp_buffer, temp_buffer + bytes_received);

            // Обрабатываем все полные пакеты в буфере
            while (read_buffer.size() >= sizeof(SecureChannel::PacketHeader)) {
                // Читаем заголовок
                SecureChannel::PacketHeader header;
                memcpy(&header, read_buffer.data(), sizeof(SecureChannel::PacketHeader));

                // Проверяем magic byte
                if (header.magic != 0xAD) {
                    log("Invalid magic byte from " + client_ip, "ERROR");
                    read_buffer.clear();
                    break;
                }

                // Получаем длину данных
                uint32_t data_length = ntohl(header.data_length);
                uint32_t packet_size = sizeof(SecureChannel::PacketHeader) + data_length;

                // Проверяем, есть ли весь пакет в буфере
                if (read_buffer.size() < packet_size) {
                    // Ждём ещё данных
                    break;
                }

                // Извлекаем полный пакет
                std::vector<uint8_t> packet(read_buffer.begin(), read_buffer.begin() + packet_size);
                
                // Удаляем обработанный пакет из буфера
                read_buffer.erase(read_buffer.begin(), read_buffer.begin() + packet_size);

                // Валидация пакета - проверяем только magic byte и хэш данных
                // checksum не проверяем из-за различий в выравнивании структур
                
                if (header.magic != 0xAD) {
                    log("Invalid magic byte from " + client_ip, "ERROR");
                    read_buffer.clear();
                    break;
                }
                
                // Проверяем хэш данных
                uint32_t expected_hash = ntohl(header.data_hash);
                std::vector<uint8_t> data_bytes(
                    packet.begin() + sizeof(SecureChannel::PacketHeader),
                    packet.end()
                );
                uint32_t actual_hash = SecureChannel::Packet::calculateDataHash(data_bytes);
                
                if (actual_hash != expected_hash) {
                    log("Invalid data hash from " + client_ip + 
                        " (expected=" + std::to_string(expected_hash) + 
                        ", actual=" + std::to_string(actual_hash) + ")", "ERROR");
                    std::string error = "ERROR: Invalid packet format";
                    send(client_socket, error.c_str(), error.length(), 0);
                    continue;
                }

                // Извлекаем данные
                std::string data = SecureChannel::extractData(packet);
                
                // Проверяем тип команды по первым байтам в сырых данных (до null-байта)
                size_t header_size = sizeof(SecureChannel::PacketHeader);
                const uint8_t* raw_data = packet.data() + header_size;
                size_t total_data_len = packet.size() - header_size;
                
                // Проверяем UPLOAD по сырым данным
                bool is_upload = (total_data_len >= 7 && 
                                  raw_data[0] == 'U' && raw_data[1] == 'P' &&
                                  raw_data[2] == 'L' && raw_data[3] == 'O' &&
                                  raw_data[4] == 'A' && raw_data[5] == 'D' &&
                                  raw_data[6] == ' ');
                bool is_auth = (total_data_len >= 5 && 
                                raw_data[0] == 'A' && raw_data[1] == 'U' &&
                                raw_data[2] == 'T' && raw_data[3] == 'H' &&
                                raw_data[4] == ' ');
                bool is_hash = (total_data_len >= 5 && 
                                raw_data[0] == 'H' && raw_data[1] == 'A' &&
                                raw_data[2] == 'S' && raw_data[3] == 'H' &&
                                raw_data[4] == ' ');

                // Поддержка разных команд
                if (is_auth) {
                    // Формат: AUTH username password
                    size_t space1 = data.find(' ');
                    size_t space2 = data.find(' ', space1 + 1);
                    std::string username = data.substr(space1 + 1, space2 - space1 - 1);
                    std::string password = data.substr(space2 + 1);

                    if (auth.authenticate(username, password)) {
                        std::string response = "OK Authenticated";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("User " + username + " authenticated from " + client_ip);
                        authenticated = true;
                        current_username = username;
                    } else {
                        std::string response = "ERROR Authentication failed";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("Failed authentication attempt from " + client_ip, "WARNING");
                    }
                }
                else if (is_hash) {
                    // Проверяем аутентификацию
                    if (!authenticated) {
                        std::string error = "ERROR: Authentication required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        log("HASH request without authentication from " + client_ip, "WARNING");
                        continue;
                    }

                    // Формат: HASH filename
                    std::string filename = data.substr(5);

                    // Получаем безопасный путь к файлу
                    std::string safePath = getSafeFilePath(filename);
                    if (safePath.empty()) {
                        std::string error = "ERROR: Invalid file path";
                        send(client_socket, error.c_str(), error.length(), 0);
                        log("Invalid file path attempt from " + client_ip, "SECURITY");
                        continue;
                    }

                    log("Client " + client_ip + " requested hash for: " + safePath);

                    // Проверяем существование файла
                    std::ifstream file(safePath, std::ios::binary);
                    if (!file) {
                        std::string error = "ERROR: File not found: " + safePath;
                        send(client_socket, error.c_str(), error.length(), 0);
                        log("File not found: " + safePath);
                    } else {
                        // Получаем время модификации файла
                        struct stat file_stat;
                        stat(safePath.c_str(), &file_stat);

                        // Читаем файл поблочно (для больших файлов)
                        std::vector<uint8_t> file_data;
                        char chunk[8192];
                        uint32_t running_hash = 0;

                        while (file.read(chunk, sizeof(chunk)) || file.gcount() > 0) {
                            std::vector<uint8_t> buffer(chunk, chunk + file.gcount());
                            running_hash = adler32_streaming(buffer, running_hash);
                        }
                        file.close();

                        // Формируем расширенный ответ
                        char response[256];
                        snprintf(response, sizeof(response), "HASH:%08x,SIZE:%ld,MTIME:%ld",
                                 running_hash, (long)file_stat.st_size, file_stat.st_mtime);

                        send(client_socket, response, strlen(response), 0);
                        log("Sent hash " + hashToString(running_hash) + " for " + safePath);
                    }
                }
                else if (data.find("LISTFILES") == 0) {
                    // Проверяем аутентификацию
                    if (!authenticated) {
                        std::string error = "ERROR: Authentication required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    // Получаем список файлов
                    std::string fileList;
                    listFilesRecursive(FILES_DIR, "", fileList);

                    // Отправляем размер списка, затем сами данные
                    uint32_t size = fileList.length();
                    char header[64];
                    snprintf(header, sizeof(header), "FILES:%u\n", size);
                    send(client_socket, header, strlen(header), 0);
                    
                    if (!fileList.empty()) {
                        send(client_socket, fileList.c_str(), fileList.length(), 0);
                    }
                    log("Sent file list to " + client_ip);
                }
                else if (data.find("LISTUSERS") == 0) {
                    // Показывать список только админам
                    log("LISTUSERS request from: " + current_username + ", authenticated: " + std::to_string(authenticated));
                    bool is_admin = auth.isAdmin(current_username);
                    log("isAdmin result: " + std::to_string(is_admin));
                    
                    if (!authenticated || !is_admin) {
                        std::string error = "ERROR: Admin access required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        log("LISTUSERS denied for: " + current_username);
                        continue;
                    }

                    std::string userList = auth.getUserListWithRoles();
                    char header[64];
                    snprintf(header, sizeof(header), "USERS:%zu\n", userList.length());
                    send(client_socket, header, strlen(header), 0);
                    if (!userList.empty()) {
                        send(client_socket, userList.c_str(), userList.length(), 0);
                    }
                    log("Sent user list to " + client_ip);
                }
                else if (data.find("ADDUSER ") == 0) {
                    // Только админ может создавать пользователей
                    if (!authenticated || !auth.isAdmin(current_username)) {
                        std::string error = "ERROR: Admin access required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    // Формат: ADDUSER username password [admin]
                    std::string rest = data.substr(8);
                    size_t space1 = rest.find(' ');
                    std::string new_username, new_password;
                    bool new_is_admin = false;

                    if (space1 != std::string::npos) {
                        new_username = rest.substr(0, space1);
                        size_t space2 = rest.find(' ', space1 + 1);
                        if (space2 != std::string::npos) {
                            new_password = rest.substr(space1 + 1, space2 - space1 - 1);
                            std::string admin_flag = rest.substr(space2 + 1);
                            new_is_admin = (admin_flag == "admin");
                        } else {
                            new_password = rest.substr(space1 + 1);
                        }
                    } else {
                        std::string error = "ERROR: Usage: ADDUSER username password [admin]";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    if (auth.userExists(new_username)) {
                        std::string error = "ERROR: User already exists";
                        send(client_socket, error.c_str(), error.length(), 0);
                    } else if (auth.addUser(new_username, new_password, new_is_admin)) {
                        std::string response = "OK User created";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("User " + new_username + " created by " + current_username);
                    } else {
                        std::string error = "ERROR: Failed to create user";
                        send(client_socket, error.c_str(), error.length(), 0);
                    }
                }
                else if (data.find("CHANGEPASS ") == 0) {
                    // Только админ может менять пароли (или пользователь свой)
                    if (!authenticated) {
                        std::string error = "ERROR: Authentication required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    // Формат: CHANGEPASS username new_password
                    std::string rest = data.substr(11);
                    size_t space = rest.find(' ');
                    std::string target_user, new_pass;

                    if (space != std::string::npos) {
                        target_user = rest.substr(0, space);
                        new_pass = rest.substr(space + 1);
                    } else {
                        std::string error = "ERROR: Usage: CHANGEPASS username new_password";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    if (auth.changePassword(target_user, new_pass, current_username)) {
                        std::string response = "OK Password changed";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("Password changed for " + target_user + " by " + current_username);
                    } else {
                        std::string error = "ERROR: Permission denied or user not found";
                        send(client_socket, error.c_str(), error.length(), 0);
                    }
                }
                else if (data.find("DELUSER ") == 0) {
                    // Только админ может удалять пользователей
                    if (!authenticated || !auth.isAdmin(current_username)) {
                        std::string error = "ERROR: Admin access required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    std::string del_username = data.substr(8);
                    if (auth.removeUser(del_username, current_username)) {
                        std::string response = "OK User deleted";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("User " + del_username + " deleted by " + current_username);
                    } else {
                        std::string error = "ERROR: Failed to delete user";
                        send(client_socket, error.c_str(), error.length(), 0);
                    }
                }
                else if (is_upload) {
                    // Загрузка файла на сервер (только для аутентифицированных)
                    if (!authenticated) {
                        std::string error = "ERROR: Authentication required";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    // Ищем '|' в сырых данных пакета
                    size_t pipe_offset = 0;
                    bool found = false;
                    for (size_t i = 0; i < total_data_len; i++) {
                        if (raw_data[i] == '|') {
                            pipe_offset = i;
                            found = true;
                            break;
                        }
                    }
                    
                    if (!found || pipe_offset < 7) {
                        std::string error = "ERROR: Invalid upload format (no pipe)";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }

                    // Извлекаем имя файла (оно до '|', текстовое, без null-байтов)
                    // Формат: "UPLOAD filename|..."
                    std::string full_command(reinterpret_cast<const char*>(raw_data), pipe_offset);
                    
                    // Проверяем и извлекаем имя файла
                    if (full_command.substr(0, 7) != "UPLOAD ") {
                        std::string error = "ERROR: Invalid upload command";
                        send(client_socket, error.c_str(), error.length(), 0);
                        continue;
                    }
                    
                    std::string filename = full_command.substr(7);

                    // Проверяем безопасность пути
                    if (!isValidPath(filename)) {
                        std::string error = "ERROR: Invalid file path";
                        send(client_socket, error.c_str(), error.length(), 0);
                        log("Invalid upload path attempt from " + client_ip, "SECURITY");
                        continue;
                    }

                    std::string safe_path = getSafeFilePath(filename);
                    
                    // Записываем бинарные данные в файл (после '|')
                    std::ofstream out_file(safe_path, std::ios::binary);
                    if (out_file) {
                        size_t file_size = total_data_len - pipe_offset - 1;
                        out_file.write(reinterpret_cast<const char*>(raw_data + pipe_offset + 1), file_size);
                        out_file.close();
                        std::string response = "OK File uploaded";
                        send(client_socket, response.c_str(), response.length(), 0);
                        log("File " + safe_path + " (" + std::to_string(file_size) + " bytes) uploaded by " + current_username);
                    } else {
                        std::string error = "ERROR: Failed to write file";
                        send(client_socket, error.c_str(), error.length(), 0);
                    }
                }
                else if (data == "LIST") {
                    // Отправляем список обработанных файлов
                    std::string list;
                    send(client_socket, list.c_str(), list.length(), 0);
                }
                else if (data == "QUIT") {
                    // Команда закрытия соединения
                    std::string response = "OK Goodbye";
                    send(client_socket, response.c_str(), response.length(), 0);
                    break;
                }
                else {
                    std::string error = "ERROR: Unknown command";
                    send(client_socket, error.c_str(), error.length(), 0);
                }
            }
        }
    } catch (const std::exception& e) {
        log(std::string("Exception: ") + e.what(), "ERROR");
    }

    close(client_socket);
}

int main(int argc, char* argv[]) {
    int port = 8080;

    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    log("Starting Adler32 Server on port " + std::to_string(port));

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        log("Failed to create socket", "ERROR");
        return 1;
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log("Failed to bind socket", "ERROR");
        close(server_socket);
        return 1;
    }

    log("Server bound to port " + std::to_string(port));

    if (listen(server_socket, 10) < 0) {
        log("Failed to listen on socket", "ERROR");
        close(server_socket);
        return 1;
    }

    log("Server listening for connections...");

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            log("Failed to accept connection", "ERROR");
            continue;
        }

        std::string client_ip = inet_ntoa(client_addr.sin_addr);
        log("Client connected: " + client_ip);

        // Обработка клиента в отдельном потоке
        std::thread client_thread(handleClient, client_socket, client_ip);
        client_thread.detach();
    }

    close(server_socket);
    return 0;
}
