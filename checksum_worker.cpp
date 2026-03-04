#include "checksum_worker.h"
#include <QFileInfo>
#include <QDateTime>

ChecksumWorker::ChecksumWorker(QObject *parent)
    : QObject(parent)
    , m_isComputing(false)
{
}

ChecksumWorker::~ChecksumWorker()
{
    if (m_future.isRunning()) {
        m_future.cancel();
        m_future.waitForFinished();
    }
}

void ChecksumWorker::computeChecksum(const QString& filePath)
{
    if (m_isComputing) {
        emit errorOccurred("Вычисление уже выполняется");
        return;
    }
    
    m_filePath = filePath;
    m_isComputing = true;
    
    // Запускаем вычисление в отдельном потоке
    m_future = QtConcurrent::run(this, &ChecksumWorker::processChecksum);
}

void ChecksumWorker::processChecksum()
{
    QString result = computeAdler32(m_filePath);
    m_isComputing = false;
    
    if (result.isEmpty()) {
        emit errorOccurred("Не удалось вычислить контрольную сумму");
    } else {
        emit checksumReady(result);
    }
}

QString ChecksumWorker::computeAdler32(const QString& filePath)
{
    QFile file(filePath);
    
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred("Не удалось открыть файл: " + filePath);
        return "";
    }
    
    const uint32_t MOD_ADLER = 65521;
    uint32_t a = 1;
    uint32_t b = 0;
    
    // Оптимизированное чтение блоками по 64KB
    const size_t BUFFER_SIZE = 65536;
    char buffer[BUFFER_SIZE];
    
    qint64 bytesRead;
    while ((bytesRead = file.read(buffer, BUFFER_SIZE)) > 0) {
        for (qint64 i = 0; i < bytesRead; i++) {
            a = (a + static_cast<uint8_t>(buffer[i])) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
    }
    
    file.close();
    
    uint32_t checksum = (b << 16) | a;
    
    // Форматируем как 8-значное шестнадцатеричное число
    return QString("%1").arg(checksum, 8, 16, QChar('0'));
}

uint32_t ChecksumWorker::adler32(const QByteArray& data, uint32_t previous)
{
    const uint32_t MOD_ADLER = 65521;
    uint32_t a = previous & 0xFFFF;
    uint32_t b = (previous >> 16) & 0xFFFF;
    
    for (int i = 0; i < data.size(); i++) {
        a = (a + static_cast<uint8_t>(data[i])) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    
    return (b << 16) | a;
}
