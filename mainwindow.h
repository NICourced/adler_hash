#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QTcpSocket>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QProgressBar>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>
#include <QDialog>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class ChecksumWorker;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Выбор файла
    void onBrowseLocalFile();
    void onBrowseRemoteFile();
    
    // Вычисление контрольной суммы
    void onComputeLocalChecksum();
    void onGetRemoteChecksum();
    void onCompareChecksums();
    
    // Обновление UI
    void onLocalChecksumReady(const QString& checksum);
    void onRemoteChecksumReady(const QString& checksum);
    void onConnectionStatusChanged(bool connected);
    void onError(const QString& error);
    
    // Аутентификация
    void onAuthenticate();
    void onConnect();
    void onDisconnect();

    // Управление пользователями
    void onManageUsers();
    void onChangePassword();
    void onUploadFile();

private:
    void setupUI();
    void setupConnections();
    bool connectToServer();
    void disconnectFromServer();
    QString computeAdler32(const QString& filePath);
    void log(const QString& message);
    void checkAdminStatus(const QString& username);
    
    // Элементы интерфейса
    QWidget *centralWidget;
    
    // Группа подключения к серверу
    QGroupBox *serverGroup;
    QLineEdit *serverHostEdit;
    QLineEdit *serverPortEdit;
    QPushButton *connectButton;
    QPushButton *disconnectButton;
    QLabel *connectionStatusLabel;
    
    // Группа аутентификации
    QGroupBox *authGroup;
    QLineEdit *usernameEdit;
    QLineEdit *passwordEdit;
    QPushButton *authButton;
    QLabel *authStatusLabel;
    
    // Группа локального файла
    QGroupBox *localFileGroup;
    QLineEdit *localFileEdit;
    QPushButton *browseLocalButton;
    QPushButton *computeLocalButton;
    QLabel *localChecksumLabel;
    QLabel *localChecksumResult;
    
    // Группа удаленного файла
    QGroupBox *remoteFileGroup;
    QLineEdit *remoteFileEdit;
    QPushButton *browseRemoteButton;
    QPushButton *getRemoteButton;
    QLabel *remoteChecksumLabel;
    QLabel *remoteChecksumResult;
    
    // Группа сравнения
    QGroupBox *compareGroup;
    QPushButton *compareButton;
    QLabel *compareResultLabel;
    
    // Лог событий
    QTextEdit *logEdit;

    // Группа администрирования (видима только для админа)
    QGroupBox *adminGroup;
    QPushButton *manageUsersButton;
    QPushButton *changePasswordButton;
    QPushButton *uploadFileButton;
    QLabel *adminStatusLabel;

    // Сокет и состояние
    QTcpSocket *socket;
    bool connected;
    bool authenticated;
    bool isAdmin;

    // Worker для фонового вычисления хэша
    ChecksumWorker *checksumWorker;
};

#endif // MAINWINDOW_H
