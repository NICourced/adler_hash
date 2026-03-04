// secure_channel.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h> // для htonl, ntohl

class SecureChannel {
private:
    static constexpr uint8_t MAGIC_BYTE = 0xAD;
    static constexpr uint32_t PROTOCOL_VERSION = 0x01;
    
public:
    #pragma pack(push, 1)  // Упаковываем структуру без выравнивания
    struct PacketHeader {
        uint8_t magic;        // 0xAD - маркер начала пакета
        uint32_t version;     // Версия протокола
        uint32_t sequence;    // Номер последовательности
        uint32_t timestamp;   // Временная метка
        uint32_t data_length; // Длина данных
        uint32_t data_hash;   // Adler-32 хэш данных
        uint32_t checksum;    // Контрольная сумма заголовка
    };
    #pragma pack(pop)
    
    struct Packet {
        PacketHeader header;
        std::vector<uint8_t> data;
        
        // Вычислить хэш данных (Adler-32)
        static uint32_t calculateDataHash(const std::vector<uint8_t>& data) {
            uint32_t a = 1, b = 0;
            const uint32_t MOD_ADLER = 65521;
            
            for (uint8_t byte : data) {
                a = (a + byte) % MOD_ADLER;
                b = (b + a) % MOD_ADLER;
            }
            
            return (b << 16) | a;
        }
        
        // Вычислить контрольную сумму заголовка
        static uint32_t calculateHeaderChecksum(const PacketHeader& header) {
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&header);
            uint32_t sum = 0;
            
            // Пропускаем поле checksum при вычислении
            for (size_t i = 0; i < sizeof(PacketHeader) - sizeof(uint32_t); i++) {
                sum += bytes[i];
            }
            
            return sum;
        }
    };
    
    // Создать пакет из данных
    static std::vector<uint8_t> createPacket(uint32_t sequence, 
                                             const std::string& data) {
        Packet packet;
        std::vector<uint8_t> result;
        
        // Заполняем заголовок
        packet.header.magic = MAGIC_BYTE;
        packet.header.version = htonl(PROTOCOL_VERSION);
        packet.header.sequence = htonl(sequence);
        packet.header.timestamp = htonl(static_cast<uint32_t>(time(nullptr)));
        packet.header.data_length = htonl(data.length());
        
        // Копируем данные
        packet.data.assign(data.begin(), data.end());
        
        // Вычисляем хэш данных
        packet.header.data_hash = htonl(Packet::calculateDataHash(packet.data));
        
        // Вычисляем контрольную сумму заголовка
        packet.header.checksum = htonl(Packet::calculateHeaderChecksum(packet.header));
        
        // Сериализуем в байты
        const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&packet.header);
        result.insert(result.end(), header_bytes, header_bytes + sizeof(PacketHeader));
        result.insert(result.end(), packet.data.begin(), packet.data.end());
        
        return result;
    }
    
    // Проверить валидность пакета
    static bool validatePacket(const std::vector<uint8_t>& packet) {
        if (packet.size() < sizeof(PacketHeader)) {
            return false; // Слишком маленький пакет
        }
        
        PacketHeader header;
        memcpy(&header, packet.data(), sizeof(PacketHeader));
        
        // Проверяем magic byte
        if (header.magic != MAGIC_BYTE) {
            return false;
        }
        
        // Проверяем контрольную сумму заголовка
        uint32_t expected_checksum = Packet::calculateHeaderChecksum(header);
        if (ntohl(header.checksum) != expected_checksum) {
            return false;
        }
        
        // Проверяем длину данных
        uint32_t data_length = ntohl(header.data_length);
        if (packet.size() != sizeof(PacketHeader) + data_length) {
            return false;
        }
        
        // Проверяем хэш данных
        if (data_length > 0) {
            std::vector<uint8_t> data(
                packet.begin() + sizeof(PacketHeader),
                packet.end()
            );
            
            uint32_t expected_hash = ntohl(header.data_hash);
            uint32_t actual_hash = Packet::calculateDataHash(data);
            
            if (actual_hash != expected_hash) {
                return false; // Данные повреждены
            }
        }
        
        return true;
    }
    
    // Извлечь данные из пакета
    static std::string extractData(const std::vector<uint8_t>& packet) {
        if (!validatePacket(packet)) {
            return "";
        }
        
        PacketHeader header;
        memcpy(&header, packet.data(), sizeof(PacketHeader));
        
        uint32_t data_length = ntohl(header.data_length);
        
        if (data_length > 0) {
            return std::string(
                packet.begin() + sizeof(PacketHeader),
                packet.begin() + sizeof(PacketHeader) + data_length
            );
        }
        
        return "";
    }
    
    // Получить номер последовательности из пакета
    static uint32_t getSequence(const std::vector<uint8_t>& packet) {
        if (packet.size() < sizeof(PacketHeader)) return 0;
        
        PacketHeader header;
        memcpy(&header, packet.data(), sizeof(PacketHeader));
        
        return ntohl(header.sequence);
    }
};