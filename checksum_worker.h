#ifndef CHECKSUM_WORKER_H
#define CHECKSUM_WORKER_H

#include <QObject>
#include <QString>
#include <QFuture>
#include <QtConcurrent>

class ChecksumWorker : public QObject
{
    Q_OBJECT

public:
    explicit ChecksumWorker(QObject *parent = nullptr);
    ~ChecksumWorker();
    
    // Вычислить контрольную сумму файла в фоне
    void computeChecksum(const QString& filePath);

signals:
    void checksumReady(const QString& checksum);
    void errorOccurred(const QString& error);

private slots:
    void processChecksum();

private:
    QString computeAdler32(const QString& filePath);
    uint32_t adler32(const QByteArray& data, uint32_t previous = 0);
    
    QString m_filePath;
    QFuture<void> m_future;
    bool m_isComputing;
};

#endif // CHECKSUM_WORKER_H
