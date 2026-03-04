// auth.h
#pragma once
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <random>
#include <iomanip>
#include <chrono>
#include <set>

class Authentication {
private:
    std::map<std::string, std::string> user_hashes; // username -> password_hash
    std::map<std::string, bool> user_admin;         // username -> is_admin
    std::map<std::string, std::chrono::steady_clock::time_point> sessions;
    std::string users_file = "users.dat";

    // Соль для хэширования паролей
    static constexpr const char* PEPPER = "AdlerSecureSalt2026";

    // Простая функция хэширования (в реальном проекте используйте bcrypt/scrypt)
    std::string simpleHash(const std::string& input) {
        uint32_t a = 1, b = 0;
        const uint32_t MOD_ADLER = 65521;

        for (char c : input) {
            a = (a + static_cast<uint8_t>(c)) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }

        uint32_t hash = (b << 16) | a;

        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << hash;
        return ss.str();
    }

    void loadUsers() {
        std::ifstream file(users_file);
        if (!file.is_open()) {
            // Создаём дефолтного админа с правами суперпользователя
            // Напрямую добавляем в память, без сохранения в файл (файл создастся позже)
            std::string salted = std::string("password") + PEPPER + "admin";
            user_hashes["admin"] = simpleHash(salted);
            user_admin["admin"] = true;
            saveUsersToFile(users_file);
            return;
        }

        user_hashes.clear();
        user_admin.clear();
        std::string line;

        while (std::getline(file, line)) {
            // Формат: username:hash:is_admin
            size_t pos1 = line.find(':');
            size_t pos2 = line.find(':', pos1 + 1);
            if (pos1 != std::string::npos && pos2 != std::string::npos) {
                std::string username = line.substr(0, pos1);
                std::string hash = line.substr(pos1 + 1, pos2 - pos1 - 1);
                bool is_admin = (line.substr(pos2 + 1) == "1");
                user_hashes[username] = hash;
                user_admin[username] = is_admin;
            }
        }
        
        file.close();

        // Если нет админа, создаём дефолтного
        if (!hasAdmin()) {
            std::string salted = std::string("password") + PEPPER + "admin";
            user_hashes["admin"] = simpleHash(salted);
            user_admin["admin"] = true;
            saveUsersToFile(users_file);
        }
    }

    bool hasAdmin() {
        for (const auto& user : user_admin) {
            if (user.second) return true;
        }
        return false;
    }
    
    // Принудительно создать админа по умолчанию
    void ensureDefaultAdmin() {
        if (!hasAdmin()) {
            addUser("admin", "password", true);
        }
    }

public:
    Authentication() {
        loadUsers();
    }

    // Добавить пользователя
    bool addUser(const std::string& username, const std::string& password, bool is_admin = false) {
        if (username.empty() || password.empty()) return false;

        std::string salted = password + PEPPER + username;
        user_hashes[username] = simpleHash(salted);
        user_admin[username] = is_admin;
        saveUsersToFile(users_file);
        return true;
    }

    // Удалить пользователя (только админ может удалять)
    bool removeUser(const std::string& username, const std::string& admin_username) {
        // Проверяем, что админ удаляет
        if (!isAdmin(admin_username)) return false;
        // Нельзя удалить самого себя
        if (username == admin_username) return false;
        
        auto it = user_hashes.find(username);
        if (it != user_hashes.end()) {
            user_hashes.erase(it);
            user_admin.erase(username);
            saveUsersToFile(users_file);
            return true;
        }
        return false;
    }

    // Изменить пароль пользователя
    bool changePassword(const std::string& username, const std::string& new_password, 
                        const std::string& requester) {
        // Админ может менять любой пароль, пользователь - только свой
        if (!isAdmin(requester) && username != requester) {
            return false;
        }
        
        if (!userExists(username) || new_password.empty()) {
            return false;
        }

        std::string salted = new_password + PEPPER + username;
        user_hashes[username] = simpleHash(salted);
        saveUsersToFile(users_file);
        return true;
    }

    // Проверить, является ли пользователь админом
    bool isAdmin(const std::string& username) {
        auto it = user_admin.find(username);
        return (it != user_admin.end() && it->second == true);
    }

    // Проверить аутентификацию
    bool authenticate(const std::string& username, const std::string& password) {
        auto it = user_hashes.find(username);
        if (it == user_hashes.end()) return false;

        std::string salted = password + PEPPER + username;
        std::string hash = simpleHash(salted);

        if (hash == it->second) {
            // Создаем сессию
            sessions[username] = std::chrono::steady_clock::now();
            return true;
        }

        return false;
    }

    // Проверить, активна ли сессия
    bool isSessionValid(const std::string& username) {
        auto it = sessions.find(username);
        if (it == sessions.end()) return false;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - it->second);

        // Сессия действительна 24 часа
        return elapsed.count() < 24;
    }

    // Завершить сессию
    void logout(const std::string& username) {
        sessions.erase(username);
    }

    // Хэшировать пароль (для внешнего использования)
    std::string hashPassword(const std::string& password) {
        return simpleHash(password);
    }

    // Сохранить пользователей в файл
    bool saveUsersToFile(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;

        for (const auto& user : user_hashes) {
            bool is_admin = user_admin[user.first];
            file << user.first << ":" << user.second << ":" << (is_admin ? "1" : "0") << std::endl;
        }

        return true;
    }

    // Загрузить пользователей из файла
    bool loadUsersFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;

        user_hashes.clear();
        user_admin.clear();
        std::string line;

        while (std::getline(file, line)) {
            size_t pos1 = line.find(':');
            size_t pos2 = line.find(':', pos1 + 1);
            if (pos1 != std::string::npos && pos2 != std::string::npos) {
                std::string username = line.substr(0, pos1);
                std::string hash = line.substr(pos1 + 1, pos2 - pos1 - 1);
                bool is_admin = (line.substr(pos2 + 1) == "1");
                user_hashes[username] = hash;
                user_admin[username] = is_admin;
            }
        }

        return true;
    }

    // Получить список пользователей
    std::vector<std::string> getUserList() {
        std::vector<std::string> users;
        for (const auto& user : user_hashes) {
            users.push_back(user.first);
        }
        return users;
    }

    // Получить список пользователей с правами
    std::string getUserListWithRoles() {
        std::string result;
        for (const auto& user : user_hashes) {
            bool is_admin = user_admin[user.first];
            result += user.first + (is_admin ? " [ADMIN]" : " [USER]") + "\n";
        }
        return result;
    }

    // Проверить, существует ли пользователь
    bool userExists(const std::string& username) {
        return user_hashes.find(username) != user_hashes.end();
    }
};