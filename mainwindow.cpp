#include "mainwindow.h"
#include "checksum_worker.h"
#include "secure_channel.h"
#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QDateTime>
#include <QThread>
#include <QDataStream>
#include <QElapsedTimer>
#include <QInputDialog>
#include <ctime>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , centralWidget(nullptr)
    , serverGroup(nullptr)
    , serverHostEdit(nullptr)
    , serverPortEdit(nullptr)
    , connectButton(nullptr)
    , disconnectButton(nullptr)
    , connectionStatusLabel(nullptr)
    , authGroup(nullptr)
    , usernameEdit(nullptr)
    , passwordEdit(nullptr)
    , authButton(nullptr)
    , authStatusLabel(nullptr)
    , localFileGroup(nullptr)
    , localFileEdit(nullptr)
    , browseLocalButton(nullptr)
    , computeLocalButton(nullptr)
    , localChecksumLabel(nullptr)
    , localChecksumResult(nullptr)
    , remoteFileGroup(nullptr)
    , remoteFileEdit(nullptr)
    , browseRemoteButton(nullptr)
    , getRemoteButton(nullptr)
    , remoteChecksumLabel(nullptr)
    , remoteChecksumResult(nullptr)
    , compareGroup(nullptr)
    , compareButton(nullptr)
    , compareResultLabel(nullptr)
    , logEdit(nullptr)
    , socket(nullptr)
    , connected(false)
    , authenticated(false)
    , isAdmin(false)
    , checksumWorker(nullptr)
{
    setupUI();
    setupConnections();
    
    setWindowTitle("Adler32 Checksum Validator");
    resize(800, 700);
}

MainWindow::~MainWindow()
{
    disconnectFromServer();
    if (checksumWorker) {
        delete checksumWorker;
    }
}

void MainWindow::setupUI()
{
    centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    
    // === Группа подключения к серверу ===
    serverGroup = new QGroupBox("Подключение к серверу");
    QHBoxLayout *serverLayout = new QHBoxLayout(serverGroup);
    
    serverHostEdit = new QLineEdit("localhost");
    serverHostEdit->setPlaceholderText("Хост сервера");
    serverHostEdit->setMaximumWidth(150);
    
    serverPortEdit = new QLineEdit("9999");
    serverPortEdit->setPlaceholderText("Порт");
    serverPortEdit->setMaximumWidth(80);
    
    connectButton = new QPushButton("Подключиться");
    disconnectButton = new QPushButton("Отключиться");
    disconnectButton->setEnabled(false);
    
    connectionStatusLabel = new QLabel("Не подключено");
    connectionStatusLabel->setStyleSheet("color: red;");
    
    serverLayout->addWidget(new QLabel("Хост:"));
    serverLayout->addWidget(serverHostEdit);
    serverLayout->addWidget(new QLabel("Порт:"));
    serverLayout->addWidget(serverPortEdit);
    serverLayout->addWidget(connectButton);
    serverLayout->addWidget(disconnectButton);
    serverLayout->addWidget(connectionStatusLabel);
    serverLayout->addStretch();
    
    // === Группа аутентификации ===
    authGroup = new QGroupBox("Аутентификация");
    QHBoxLayout *authLayout = new QHBoxLayout(authGroup);
    
    usernameEdit = new QLineEdit("admin");
    usernameEdit->setPlaceholderText("Имя пользователя");
    usernameEdit->setMaximumWidth(150);
    
    passwordEdit = new QLineEdit("admin123");
    passwordEdit->setPlaceholderText("Пароль");
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setMaximumWidth(150);
    
    authButton = new QPushButton("Войти");
    authButton->setEnabled(false);
    
    authStatusLabel = new QLabel("Не авторизован");
    authStatusLabel->setStyleSheet("color: red;");
    
    authLayout->addWidget(new QLabel("Логин:"));
    authLayout->addWidget(usernameEdit);
    authLayout->addWidget(new QLabel("Пароль:"));
    authLayout->addWidget(passwordEdit);
    authLayout->addWidget(authButton);
    authLayout->addWidget(authStatusLabel);
    authLayout->addStretch();
    
    // === Группа локального файла ===
    localFileGroup = new QGroupBox("Локальный файл");
    QFormLayout *localLayout = new QFormLayout(localFileGroup);
    
    QHBoxLayout *localFileLayout = new QHBoxLayout();
    localFileEdit = new QLineEdit();
    localFileEdit->setPlaceholderText("Путь к локальному файлу");
    browseLocalButton = new QPushButton("Обзор...");
    browseLocalButton->setMaximumWidth(80);
    localFileLayout->addWidget(localFileEdit);
    localFileLayout->addWidget(browseLocalButton);
    
    computeLocalButton = new QPushButton("Вычислить Adler32");
    
    localChecksumLabel = new QLabel("Локальная контрольная сумма:");
    localChecksumResult = new QLabel("—");
    localChecksumResult->setFont(QFont("Courier", 10, QFont::Bold));
    localChecksumResult->setFrameStyle(QFrame::Panel | QFrame::Sunken);
    
    localLayout->addRow("Файл:", localFileLayout);
    localLayout->addRow(computeLocalButton);
    localLayout->addRow(localChecksumLabel, localChecksumResult);
    
    // === Группа удаленного файла ===
    remoteFileGroup = new QGroupBox("Файл на сервере");
    QFormLayout *remoteLayout = new QFormLayout(remoteFileGroup);
    
    QHBoxLayout *remoteFileLayout = new QHBoxLayout();
    remoteFileEdit = new QLineEdit();
    remoteFileEdit->setPlaceholderText("Путь к файлу на сервере");
    browseRemoteButton = new QPushButton("Обзор...");
    browseRemoteButton->setMaximumWidth(80);
    remoteFileLayout->addWidget(remoteFileEdit);
    remoteFileLayout->addWidget(browseRemoteButton);
    
    getRemoteButton = new QPushButton("Получить Adler32");
    getRemoteButton->setEnabled(false);
    
    remoteChecksumLabel = new QLabel("Серверная контрольная сумма:");
    remoteChecksumResult = new QLabel("—");
    remoteChecksumResult->setFont(QFont("Courier", 10, QFont::Bold));
    remoteChecksumResult->setFrameStyle(QFrame::Panel | QFrame::Sunken);
    
    remoteLayout->addRow("Файл:", remoteFileLayout);
    remoteLayout->addRow(getRemoteButton);
    remoteLayout->addRow(remoteChecksumLabel, remoteChecksumResult);
    
    // === Группа сравнения ===
    compareGroup = new QGroupBox("Сравнение контрольных сумм");
    QVBoxLayout *compareLayout = new QVBoxLayout(compareGroup);
    
    compareButton = new QPushButton("Сравнить локальную и серверную контрольные суммы");
    compareButton->setEnabled(false);
    
    compareResultLabel = new QLabel("Результат сравнения: —");
    compareResultLabel->setFont(QFont("Arial", 11, QFont::Bold));
    compareResultLabel->setAlignment(Qt::AlignCenter);
    
    compareLayout->addWidget(compareButton);
    compareLayout->addWidget(compareResultLabel);
    
    // === Лог событий ===
    logEdit = new QTextEdit();
    logEdit->setReadOnly(true);
    logEdit->setMaximumHeight(150);
    logEdit->setPlaceholderText("Журнал событий...");

    // === Группа администрирования (скрыта по умолчанию) ===
    adminGroup = new QGroupBox("Панель администратора");
    adminGroup->setVisible(false);  // Скрыта пока не подтверждён статус админа
    
    QVBoxLayout *adminLayout = new QVBoxLayout(adminGroup);
    
    adminStatusLabel = new QLabel("Статус: не проверен");
    adminStatusLabel->setStyleSheet("color: orange; font-weight: bold;");
    adminLayout->addWidget(adminStatusLabel);

    QHBoxLayout *adminButtonsLayout = new QHBoxLayout();
    manageUsersButton = new QPushButton("Управление пользователями");
    manageUsersButton->setEnabled(false);

    changePasswordButton = new QPushButton("Сменить пароль");
    changePasswordButton->setEnabled(false);

    uploadFileButton = new QPushButton("Загрузить файл на сервер");
    uploadFileButton->setEnabled(false);

    adminButtonsLayout->addWidget(manageUsersButton);
    adminButtonsLayout->addWidget(changePasswordButton);
    adminButtonsLayout->addWidget(uploadFileButton);
    adminLayout->addLayout(adminButtonsLayout);

    // === Сборка основного макета ===
    mainLayout->addWidget(serverGroup);
    mainLayout->addWidget(authGroup);
    mainLayout->addWidget(localFileGroup);
    mainLayout->addWidget(remoteFileGroup);
    mainLayout->addWidget(compareGroup);
    mainLayout->addWidget(adminGroup);
    mainLayout->addWidget(new QLabel("Журнал событий:"));
    mainLayout->addWidget(logEdit);
}

void MainWindow::setupConnections()
{
    connect(connectButton, &QPushButton::clicked, this, &MainWindow::onConnect);
    connect(disconnectButton, &QPushButton::clicked, this, &MainWindow::onDisconnect);
    connect(authButton, &QPushButton::clicked, this, &MainWindow::onAuthenticate);

    connect(browseLocalButton, &QPushButton::clicked, this, &MainWindow::onBrowseLocalFile);
    connect(browseRemoteButton, &QPushButton::clicked, this, &MainWindow::onBrowseRemoteFile);

    connect(computeLocalButton, &QPushButton::clicked, this, &MainWindow::onComputeLocalChecksum);
    connect(getRemoteButton, &QPushButton::clicked, this, &MainWindow::onGetRemoteChecksum);
    connect(compareButton, &QPushButton::clicked, this, &MainWindow::onCompareChecksums);

    connect(manageUsersButton, &QPushButton::clicked, this, &MainWindow::onManageUsers);
    connect(changePasswordButton, &QPushButton::clicked, this, &MainWindow::onChangePassword);
    connect(uploadFileButton, &QPushButton::clicked, this, &MainWindow::onUploadFile);

    // Создаем worker для фонового вычисления хэша
    checksumWorker = new ChecksumWorker();
    connect(checksumWorker, &ChecksumWorker::checksumReady, this, &MainWindow::onLocalChecksumReady);
    connect(checksumWorker, &ChecksumWorker::errorOccurred, this, &MainWindow::onError);
}

void MainWindow::log(const QString& message)
{
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    logEdit->append(QString("[%1] %2").arg(timestamp, message));
}

void MainWindow::onConnect()
{
    if (connectToServer()) {
        connected = true;
        connectButton->setEnabled(false);
        disconnectButton->setEnabled(true);
        authButton->setEnabled(true);
        connectionStatusLabel->setText("Подключено");
        connectionStatusLabel->setStyleSheet("color: green;");
        log("Подключено к серверу " + serverHostEdit->text() + ":" + serverPortEdit->text());
    }
}

void MainWindow::onDisconnect()
{
    disconnectFromServer();
    connected = false;
    authenticated = false;
    isAdmin = false;
    connectButton->setEnabled(true);
    disconnectButton->setEnabled(false);
    authButton->setEnabled(false);
    getRemoteButton->setEnabled(false);
    browseRemoteButton->setEnabled(false);
    manageUsersButton->setEnabled(false);
    changePasswordButton->setEnabled(false);
    uploadFileButton->setEnabled(false);
    adminGroup->setVisible(false);
    connectionStatusLabel->setText("Не подключено");
    connectionStatusLabel->setStyleSheet("color: red;");
    authStatusLabel->setText("Не авторизован");
    authStatusLabel->setStyleSheet("color: red;");
    log("Отключено от сервера");
}

bool MainWindow::connectToServer()
{
    if (socket) {
        delete socket;
    }
    
    socket = new QTcpSocket(this);
    
    QString host = serverHostEdit->text().trimmed();
    int port = serverPortEdit->text().toInt();
    
    socket->connectToHost(host, port);
    
    if (!socket->waitForConnected(5000)) {
        log("Ошибка подключения: " + socket->errorString());
        return false;
    }
    
    return true;
}

void MainWindow::disconnectFromServer()
{
    if (socket) {
        socket->disconnectFromHost();
        socket->waitForDisconnected(1000);
        delete socket;
        socket = nullptr;
    }
}

void MainWindow::onAuthenticate()
{
    if (!socket || !connected) {
        QMessageBox::warning(this, "Ошибка", "Сначала подключитесь к серверу");
        return;
    }

    QString username = usernameEdit->text().trimmed();
    QString password = passwordEdit->text();

    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите логин и пароль");
        return;
    }

    // Формируем команду AUTH
    QString authCmd = "AUTH " + username + " " + password;

    // Создаем пакет в формате SecureChannel
    std::string data = authCmd.toUtf8().constData();
    std::vector<uint8_t> packet = SecureChannel::createPacket(1, data);

    socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    socket->waitForBytesWritten();

    // Ждем ответ
    if (socket->waitForReadyRead(5000)) {
        QByteArray response = socket->readAll();
        QString respStr(response);

        if (respStr.startsWith("OK")) {
            authenticated = true;
            authStatusLabel->setText("Авторизован");
            authStatusLabel->setStyleSheet("color: green;");
            getRemoteButton->setEnabled(true);
            browseRemoteButton->setEnabled(true);
            log("Аутентификация успешна для пользователя: " + username);
            
            // Проверяем, является ли пользователь админом
            checkAdminStatus(username);
        } else {
            authStatusLabel->setText("Ошибка аутентификации");
            authStatusLabel->setStyleSheet("color: red;");
            log("Ошибка аутентификации: " + respStr);
        }
    } else {
        log("Таймаут ответа сервера");
    }
}

void MainWindow::checkAdminStatus(const QString& username)
{
    // Очищаем буфер сокета перед отправкой новой команды
    socket->readAll();
    
    // Отправляем команду LISTUSERS для проверки статуса
    QString listCmd = "LISTUSERS";
    std::string data = listCmd.toUtf8().constData();
    std::vector<uint8_t> packet = SecureChannel::createPacket(4, data);

    socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    socket->waitForBytesWritten();

    // Ждем ответ
    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    int timeout = 3000;

    while (timer.elapsed() < timeout) {
        if (socket->waitForReadyRead(100)) {
            response += socket->readAll();
            // Проверяем, есть ли заголовок USERS:
            if (response.contains("USERS:")) {
                // Пробуем найти длину данных
                int colonPos = response.indexOf("USERS:");
                int newlinePos = response.indexOf('\n', colonPos);
                if (newlinePos > 0) {
                    // Получаем длину данных после заголовка
                    uint expectedSize = response.mid(colonPos + 6, newlinePos - colonPos - 6).toUInt();
                    // Получаем текущий размер данных после newline
                    int currentSize = response.size() - newlinePos - 1;
                    
                    // Если данных ещё недостаточно, ждём ещё
                    if (currentSize >= (int)expectedSize) {
                        break;  // Все данные получены
                    }
                } else {
                    // Нет newline, ждём ещё
                    continue;
                }
            }
        }
    }

    log("Ответ LISTUSERS (" + QString::number(response.size()) + " байт): " + response);
    
    // Если ошибка доступа - значит не админ
    if (response.contains("ERROR:")) {
        isAdmin = false;
        adminStatusLabel->setText("Статус: пользователь");
        adminStatusLabel->setStyleSheet("color: gray;");
        log("Пользователь " + username + " не имеет прав администратора");
        return;
    }
    
    if (!response.isEmpty() && response.contains("USERS:")) {
        QString respStr(response);
        // Проверяем, есть ли [ADMIN] после имени пользователя
        int newlinePos = respStr.indexOf('\n');
        if (newlinePos > 0) {
            QString userList = respStr.mid(newlinePos + 1);
            log("Список пользователей (" + QString::number(userList.size()) + " байт): " + userList);
            
            // Ищем пользователя в списке
            QStringList users = userList.split('\n', Qt::SkipEmptyParts);
            for (const QString& user : users) {
                log("Проверка пользователя: '" + user + "'");
                if (user.startsWith(username + " ")) {
                    isAdmin = user.contains("[ADMIN]");
                    log("Найден пользователь " + username + ", isAdmin=" + QString::number(isAdmin));
                    break;
                }
            }
            
            if (isAdmin) {
                adminGroup->setVisible(true);
                adminStatusLabel->setText("Статус: АДМИНИСТРАТОР");
                adminStatusLabel->setStyleSheet("color: green; font-weight: bold;");
                manageUsersButton->setEnabled(true);
                changePasswordButton->setEnabled(true);
                uploadFileButton->setEnabled(true);
                log("Пользователь " + username + " имеет права администратора");
            } else {
                isAdmin = false;
                adminGroup->setVisible(false);
                adminStatusLabel->setText("Статус: пользователь");
                adminStatusLabel->setStyleSheet("color: gray;");
                log("Пользователь " + username + " не имеет прав администратора");
            }
        }
    } else {
        // Нет ответа - предполагаем, что не админ
        isAdmin = false;
        adminGroup->setVisible(false);
        adminStatusLabel->setText("Статус: пользователь");
        adminStatusLabel->setStyleSheet("color: gray;");
        log("Не удалось получить статус пользователя");
    }
}

void MainWindow::onBrowseLocalFile()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Выберите файл", "", "Все файлы (*)");
    if (!fileName.isEmpty()) {
        localFileEdit->setText(fileName);
        localChecksumResult->setText("—");
        compareResultLabel->setText("Результат сравнения: —");
    }
}

void MainWindow::onBrowseRemoteFile()
{
    if (!socket || !authenticated) {
        QMessageBox::warning(this, "Ошибка", "Сначала подключитесь и авторизуйтесь");
        return;
    }

    log("Запрос списка файлов с сервера...");

    // Отправляем команду LISTFILES
    QString listCmd = "LISTFILES";
    std::string data = listCmd.toUtf8().constData();
    std::vector<uint8_t> packet = SecureChannel::createPacket(3, data);

    socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    socket->waitForBytesWritten();

    // Ждем ответ
    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    int timeout = 5000;

    // Сначала читаем заголовок FILES:<size>\n
    while (timer.elapsed() < timeout) {
        if (socket->waitForReadyRead(500)) {
            response += socket->readAll();
            if (response.contains("FILES:")) {
                break;
            }
        }
        if (socket->state() != QAbstractSocket::ConnectedState && response.isEmpty()) {
            break;
        }
    }

    if (!response.isEmpty() && response.contains("FILES:")) {
        QString respStr(response);
        int newlinePos = respStr.indexOf('\n');
        if (newlinePos > 0) {
            uint expectedSize = respStr.mid(6, newlinePos - 6).toUInt();
            
            // Уже прочитанные данные после заголовка
            QByteArray currentData = response.mid(newlinePos + 1);
            
            // Читаем остальные данные, пока не получим expectedSize байт
            while (currentData.size() < (int)expectedSize && timer.elapsed() < timeout) {
                if (socket->waitForReadyRead(500)) {
                    currentData += socket->readAll();
                } else {
                    break;
                }
            }
            
            log("Получено файлов: " + QString::number(currentData.size()) + " байт (ожидалось: " + QString::number(expectedSize) + ")");

            // Разбиваем на список файлов
            QString fileList(currentData);
            QStringList files = fileList.split('\n', Qt::SkipEmptyParts);

            if (files.isEmpty()) {
                QMessageBox::information(this, "Файлы на сервере", "Папка files пуста или не существует");
                return;
            }

            // Показываем диалог выбора файла
            bool ok = false;
            QString selectedFile = QInputDialog::getItem(this, "Выберите файл",
                "Файлы на сервере:", files, 0, false, &ok);

            if (ok && !selectedFile.isEmpty()) {
                remoteFileEdit->setText(selectedFile);
                remoteChecksumResult->setText("—");
                compareResultLabel->setText("Результат сравнения: —");
                compareButton->setEnabled(false);
                log("Выбран файл на сервере: " + selectedFile);
            }
        }
    } else if (!response.isEmpty() && response.contains("ERROR:")) {
        QMessageBox::warning(this, "Ошибка сервера", response);
    } else {
        log("Таймаут получения списка файлов");
        QMessageBox::warning(this, "Ошибка", "Не удалось получить список файлов с сервера");
    }
}

void MainWindow::onComputeLocalChecksum()
{
    QString filePath = localFileEdit->text().trimmed();
    
    if (filePath.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Выберите файл");
        return;
    }
    
    log("Вычисление Adler32 для файла: " + filePath);
    localChecksumResult->setText("Вычисление...");
    
    // Запускаем вычисление в фоне
    checksumWorker->computeChecksum(filePath);
}

void MainWindow::onGetRemoteChecksum()
{
    if (!socket || !authenticated) {
        QMessageBox::warning(this, "Ошибка", "Сначала подключитесь и авторизуйтесь");
        return;
    }

    QString fileName = remoteFileEdit->text().trimmed();

    if (fileName.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите путь к файлу на сервере");
        return;
    }

    log("Запрос контрольной суммы для файла на сервере: " + fileName);
    remoteChecksumResult->setText("Запрос...");

    // Формируем команду HASH
    QString hashCmd = "HASH " + fileName;

    // Создаем пакет в формате SecureChannel
    std::string data = hashCmd.toUtf8().constData();
    std::vector<uint8_t> packet = SecureChannel::createPacket(2, data);

    socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    socket->waitForBytesWritten();

    // Ждем ответ в цикле, чтобы получить все данные
    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    int timeout = 30000; // 30 секунд на вычисление хэша большого файла

    while (timer.elapsed() < timeout) {
        if (socket->waitForReadyRead(500)) {
            response += socket->readAll();
            // Если получили полный ответ (содержит HASH: или ERROR:), выходим
            if (response.contains("HASH:") || response.contains("ERROR:")) {
                break;
            }
        }
        // Проверяем, не закрыл ли сервер соединение
        if (socket->state() != QAbstractSocket::ConnectedState && response.isEmpty()) {
            break;
        }
    }

    if (!response.isEmpty()) {
        QString respStr(response);
        log("Ответ сервера: " + respStr);

        // Парсим ответ формата HASH:xxxxxxxx,SIZE:...,MTIME:...
        if (respStr.startsWith("HASH:")) {
            int commaPos = respStr.indexOf(',');
            if (commaPos > 0) {
                QString hash = respStr.mid(5, commaPos - 5).toUpper();
                remoteChecksumResult->setText(hash);
                log("Получена контрольная сумма с сервера: " + hash);
            } else {
                // Простой формат
                QString hash = respStr.mid(5).toUpper();
                remoteChecksumResult->setText(hash);
                log("Получена контрольная сумма с сервера: " + hash);
            }
            // Активируем кнопку сравнения, если локальный хеш уже вычислен
            QString localChecksum = localChecksumResult->text();
            if (localChecksum != "—" && !localChecksum.isEmpty() && 
                localChecksum != "Вычисление...") {
                compareButton->setEnabled(true);
            }
        } else if (respStr.startsWith("ERROR:")) {
            remoteChecksumResult->setText("Ошибка");
            log("Ошибка сервера: " + respStr);
            QMessageBox::warning(this, "Ошибка сервера", respStr);
        } else {
            remoteChecksumResult->setText("Неизвестный ответ");
            log("Неизвестный формат ответа: " + respStr);
        }
    } else {
        remoteChecksumResult->setText("Таймаут");
        log("Таймаут ответа сервера");
    }
}

void MainWindow::onCompareChecksums()
{
    QString localChecksum = localChecksumResult->text();
    QString remoteChecksum = remoteChecksumResult->text();
    
    if (localChecksum == "—" || localChecksum.isEmpty() || localChecksum == "Вычисление...") {
        QMessageBox::warning(this, "Ошибка", "Сначала вычислите локальную контрольную сумму");
        return;
    }
    
    if (remoteChecksum == "—" || remoteChecksum.isEmpty() || remoteChecksum == "Запрос...") {
        QMessageBox::warning(this, "Ошибка", "Сначала получите контрольную сумму с сервера");
        return;
    }
    
    // Сравниваем (приводим к верхнему регистру)
    if (localChecksum.toUpper() == remoteChecksum.toUpper()) {
        compareResultLabel->setText("✓ Контрольные суммы СОВПАДАЮТ");
        compareResultLabel->setStyleSheet("color: green;");
        log("Сравнение: контрольные суммы совпадают (" + localChecksum + ")");
    } else {
        compareResultLabel->setText("✗ Контрольные суммы НЕ совпадают");
        compareResultLabel->setStyleSheet("color: red;");
        log("Сравнение: контрольные суммы НЕ совпадают (локальная: " + localChecksum + 
            ", серверная: " + remoteChecksum + ")");
    }
}

void MainWindow::onLocalChecksumReady(const QString& checksum)
{
    localChecksumResult->setText(checksum.toUpper());
    log("Локальная контрольная сумма вычислена: " + checksum);
    
    // Активируем кнопку сравнения, если есть обе контрольные суммы
    QString remoteChecksum = remoteChecksumResult->text();
    if (remoteChecksum != "—" && !remoteChecksum.isEmpty() && 
        remoteChecksum != "Запрос..." && remoteChecksum != "Таймаут") {
        compareButton->setEnabled(true);
    }
}

void MainWindow::onRemoteChecksumReady(const QString& checksum)
{
    remoteChecksumResult->setText(checksum.toUpper());
    
    // Активируем кнопку сравнения, если есть обе контрольные суммы
    QString localChecksum = localChecksumResult->text();
    if (localChecksum != "—" && !localChecksum.isEmpty() && 
        localChecksum != "Вычисление...") {
        compareButton->setEnabled(true);
    }
}

void MainWindow::onConnectionStatusChanged(bool connected)
{
    // Может использоваться для обновления UI
}

void MainWindow::onError(const QString& error)
{
    log("Ошибка: " + error);
    QMessageBox::warning(this, "Ошибка", error);
}

QString MainWindow::computeAdler32(const QString& filePath)
{
    // Эта функция теперь вызывается через worker
    return "";
}

void MainWindow::onManageUsers()
{
    if (!socket || !authenticated || !isAdmin) {
        QMessageBox::warning(this, "Ошибка", "Доступ только для администратора");
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle("Управление пользователями");
    dialog.setMinimumWidth(400);

    QVBoxLayout *layout = new QVBoxLayout(&dialog);

    // Список пользователей
    QTextEdit *userListEdit = new QTextEdit();
    userListEdit->setReadOnly(true);
    userListEdit->setMaximumHeight(150);
    layout->addWidget(new QLabel("Пользователи:"));
    layout->addWidget(userListEdit);

    // Загрузка списка пользователей
    QString listCmd = "LISTUSERS";
    std::string data = listCmd.toUtf8().constData();
    std::vector<uint8_t> packet = SecureChannel::createPacket(4, data);
    socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    socket->waitForBytesWritten();

    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    int timeout = 3000;

    while (timer.elapsed() < timeout) {
        if (socket->waitForReadyRead(500)) {
            response += socket->readAll();
            if (response.contains("USERS:")) {
                QThread::msleep(100);
                response += socket->readAll();
                break;
            }
        }
    }

    if (!response.isEmpty() && response.contains("USERS:")) {
        QString respStr(response);
        int newlinePos = respStr.indexOf('\n');
        if (newlinePos > 0) {
            QString userList = respStr.mid(newlinePos + 1);
            userListEdit->setText(userList.replace("\n", ", "));
        }
    }

    // Создание пользователя
    QGroupBox *addGroup = new QGroupBox("Создать пользователя");
    QFormLayout *addLayout = new QFormLayout(addGroup);

    QLineEdit *newUsername = new QLineEdit();
    QLineEdit *newPassword = new QLineEdit();
    newPassword->setEchoMode(QLineEdit::Password);
    QCheckBox *isAdminCheck = new QCheckBox("Права администратора");

    addLayout->addRow("Логин:", newUsername);
    addLayout->addRow("Пароль:", newPassword);
    addLayout->addRow(isAdminCheck);

    QPushButton *addButton = new QPushButton("Создать");
    addLayout->addRow(addButton);
    layout->addWidget(addGroup);

    // Удаление пользователя
    QGroupBox *delGroup = new QGroupBox("Удалить пользователя");
    QHBoxLayout *delLayout = new QHBoxLayout(delGroup);

    QComboBox *userCombo = new QComboBox();
    QPushButton *delButton = new QPushButton("Удалить");

    delLayout->addWidget(userCombo);
    delLayout->addWidget(delButton);
    layout->addWidget(delGroup);

    // Заполняем комбобокс
    if (!response.isEmpty()) {
        QString respStr(response);
        int newlinePos = respStr.indexOf('\n');
        if (newlinePos > 0) {
            QString userList = respStr.mid(newlinePos + 1);
            QStringList users = userList.split('\n', Qt::SkipEmptyParts);
            for (const QString& user : users) {
                QString cleanUser = user;
                cleanUser.replace(" [ADMIN]", "").replace(" [USER]", "");
                if (cleanUser != "admin") { // Нельзя удалить admin
                    userCombo->addItem(cleanUser);
                }
            }
        }
    }

    connect(addButton, &QPushButton::clicked, [&]() {
        if (newUsername->text().isEmpty() || newPassword->text().isEmpty()) {
            QMessageBox::warning(&dialog, "Ошибка", "Введите логин и пароль");
            return;
        }

        QString cmd = "ADDUSER " + newUsername->text() + " " + newPassword->text();
        if (isAdminCheck->isChecked()) {
            cmd += " admin";
        }

        std::string data = cmd.toUtf8().constData();
        std::vector<uint8_t> packet = SecureChannel::createPacket(5, data);
        socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
        socket->waitForBytesWritten();

        QByteArray response;
        if (socket->waitForReadyRead(3000)) {
            response = socket->readAll();
            if (response.startsWith("OK")) {
                QMessageBox::information(&dialog, "Успех", "Пользователь создан");
                newUsername->clear();
                newPassword->clear();
                isAdminCheck->setChecked(false);
            } else {
                QMessageBox::warning(&dialog, "Ошибка", QString(response));
            }
        }
    });

    connect(delButton, &QPushButton::clicked, [&]() {
        QString username = userCombo->currentText();
        if (username.isEmpty()) {
            QMessageBox::warning(&dialog, "Ошибка", "Выберите пользователя");
            return;
        }

        QString cmd = "DELUSER " + username;
        std::string data = cmd.toUtf8().constData();
        std::vector<uint8_t> packet = SecureChannel::createPacket(6, data);
        socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
        socket->waitForBytesWritten();

        QByteArray response;
        if (socket->waitForReadyRead(3000)) {
            response = socket->readAll();
            if (response.startsWith("OK")) {
                QMessageBox::information(&dialog, "Успех", "Пользователь удален");
                userCombo->removeItem(userCombo->currentIndex());
            } else {
                QMessageBox::warning(&dialog, "Ошибка", QString(response));
            }
        }
    });

    dialog.exec();
}

void MainWindow::onChangePassword()
{
    if (!socket || !authenticated) {
        QMessageBox::warning(this, "Ошибка", "Сначала авторизуйтесь");
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle("Смена пароля");
    dialog.setMinimumWidth(300);

    QFormLayout *layout = new QFormLayout(&dialog);

    QComboBox *userCombo = new QComboBox();
    if (isAdmin) {
        // Админ может менять пароль любому пользователю
        QString listCmd = "LISTUSERS";
        std::string data = listCmd.toUtf8().constData();
        std::vector<uint8_t> packet = SecureChannel::createPacket(4, data);
        socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
        socket->waitForBytesWritten();

        QByteArray response;
        QElapsedTimer timer;
        timer.start();
        int timeout = 3000;

        while (timer.elapsed() < timeout) {
            if (socket->waitForReadyRead(500)) {
                response += socket->readAll();
                if (response.contains("USERS:")) {
                    QThread::msleep(100);
                    response += socket->readAll();
                    break;
                }
            }
        }

        if (!response.isEmpty()) {
            QString respStr(response);
            int newlinePos = respStr.indexOf('\n');
            if (newlinePos > 0) {
                QString userList = respStr.mid(newlinePos + 1);
                QStringList users = userList.split('\n', Qt::SkipEmptyParts);
                for (const QString& user : users) {
                    QString cleanUser = user;
                    cleanUser.replace(" [ADMIN]", "").replace(" [USER]", "");
                    userCombo->addItem(cleanUser);
                }
            }
        }
    } else {
        // Обычный пользователь может менять только свой пароль
        userCombo->addItem(usernameEdit->text());
        userCombo->setEnabled(false);
    }

    QLineEdit *newPassword = new QLineEdit();
    newPassword->setEchoMode(QLineEdit::Password);
    QLineEdit *confirmPassword = new QLineEdit();
    confirmPassword->setEchoMode(QLineEdit::Password);

    layout->addRow("Пользователь:", userCombo);
    layout->addRow("Новый пароль:", newPassword);
    layout->addRow("Подтверждение:", confirmPassword);

    QPushButton *okButton = new QPushButton("Сменить");
    layout->addRow(okButton);

    connect(okButton, &QPushButton::clicked, [&]() {
        if (newPassword->text().isEmpty()) {
            QMessageBox::warning(&dialog, "Ошибка", "Введите пароль");
            return;
        }
        if (newPassword->text() != confirmPassword->text()) {
            QMessageBox::warning(&dialog, "Ошибка", "Пароли не совпадают");
            return;
        }

        QString cmd = "CHANGEPASS " + userCombo->currentText() + " " + newPassword->text();
        std::string data = cmd.toUtf8().constData();
        std::vector<uint8_t> packet = SecureChannel::createPacket(7, data);
        socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
        socket->waitForBytesWritten();

        QByteArray response;
        if (socket->waitForReadyRead(3000)) {
            response = socket->readAll();
            if (response.startsWith("OK")) {
                QMessageBox::information(&dialog, "Успех", "Пароль изменен");
                dialog.accept();
            } else {
                QMessageBox::warning(&dialog, "Ошибка", QString(response));
            }
        }
    });

    dialog.exec();
}

void MainWindow::onUploadFile()
{
    if (!socket || !authenticated) {
        QMessageBox::warning(this, "Ошибка", "Сначала авторизуйтесь");
        return;
    }

    if (socket->state() != QAbstractSocket::ConnectedState) {
        QMessageBox::warning(this, "Ошибка", "Нет соединения с сервером");
        return;
    }

    QString filePath = QFileDialog::getOpenFileName(this, "Выберите файл для загрузки", "", "Все файлы (*)");
    if (filePath.isEmpty()) {
        return;
    }

    // Читаем файл
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Ошибка", "Не удалось открыть файл");
        return;
    }

    QByteArray fileData = file.readAll();
    file.close();

    // Ограничение на размер файла (1MB)
    if (fileData.size() > 1024 * 1024) {
        QMessageBox::warning(this, "Ошибка", "Файл слишком большой (макс. 1MB)");
        return;
    }

    QString fileName = QFileInfo(filePath).fileName();

    // Формируем команду UPLOAD в формате SecureChannel
    // Формат: UPLOAD filename|binary_data
    QString cmd = "UPLOAD " + fileName + "|";
    QByteArray cmdUtf8 = cmd.toUtf8();
    
    // Создаём заголовок пакета вручную (в network byte order)
    uint32_t dataLength = cmdUtf8.size() + fileData.size();
    
    std::vector<uint8_t> packet;
    packet.reserve(28 + dataLength);  // 28 bytes header + data
    
    packet.push_back(0xAD);  // Magic byte
    
    // Version (4 bytes, big-endian) = 1
    packet.push_back(0x00); packet.push_back(0x00); packet.push_back(0x00); packet.push_back(0x01);
    
    // Sequence (4 bytes, big-endian) = 8
    uint32_t seq = 8;
    packet.push_back((seq >> 24) & 0xFF);
    packet.push_back((seq >> 16) & 0xFF);
    packet.push_back((seq >> 8) & 0xFF);
    packet.push_back(seq & 0xFF);
    
    // Timestamp (4 bytes, big-endian)
    uint32_t ts = static_cast<uint32_t>(time(nullptr));
    packet.push_back((ts >> 24) & 0xFF);
    packet.push_back((ts >> 16) & 0xFF);
    packet.push_back((ts >> 8) & 0xFF);
    packet.push_back(ts & 0xFF);
    
    // Data length (4 bytes, big-endian)
    packet.push_back((dataLength >> 24) & 0xFF);
    packet.push_back((dataLength >> 16) & 0xFF);
    packet.push_back((dataLength >> 8) & 0xFF);
    packet.push_back(dataLength & 0xFF);
    
    // Data hash (4 bytes, big-endian) - вычисляем для всех данных
    uint32_t a = 1, b = 0;
    const uint32_t MOD_ADLER = 65521;
    for (char c : cmdUtf8) {
        a = (a + static_cast<uint8_t>(c)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    for (char c : fileData) {
        a = (a + static_cast<uint8_t>(c)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    uint32_t dataHash = (b << 16) | a;
    packet.push_back((dataHash >> 24) & 0xFF);
    packet.push_back((dataHash >> 16) & 0xFF);
    packet.push_back((dataHash >> 8) & 0xFF);
    packet.push_back(dataHash & 0xFF);
    
    // Header checksum (4 bytes, big-endian) - сумма всех байт заголовка кроме checksum (24 байта)
    uint32_t checksum = 0;
    for (size_t i = 0; i < 24; i++) {
        checksum += packet[i];
    }
    packet.push_back((checksum >> 24) & 0xFF);
    packet.push_back((checksum >> 16) & 0xFF);
    packet.push_back((checksum >> 8) & 0xFF);
    packet.push_back(checksum & 0xFF);
    
    // Добавляем данные (команда + файл)
    for (char c : cmdUtf8) {
        packet.push_back(static_cast<uint8_t>(c));
    }
    for (char c : fileData) {
        packet.push_back(static_cast<uint8_t>(c));
    }

    log("Загрузка файла на сервер: " + fileName + " (" + QString::number(fileData.size()) + " байт, пакет=" + QString::number(packet.size()) + ")");
    
    // Отправляем пакет
    qint64 bytesWritten = socket->write(reinterpret_cast<const char*>(packet.data()), packet.size());
    if (bytesWritten < 0) {
        log("Ошибка отправки: " + socket->errorString());
        QMessageBox::warning(this, "Ошибка", "Ошибка отправки данных: " + socket->errorString());
        return;
    }
    log("Отправлено " + QString::number(bytesWritten) + " байт");

    // Ждем ответ
    QByteArray response;
    QElapsedTimer timer;
    timer.start();
    int timeout = 10000;

    while (timer.elapsed() < timeout && socket->state() == QAbstractSocket::ConnectedState) {
        if (socket->waitForReadyRead(500)) {
            response = socket->readAll();
            if (!response.isEmpty()) break;
        }
    }

    if (!response.isEmpty()) {
        log("Ответ сервера: " + response);
        if (response.startsWith("OK")) {
            log("Файл загружен: " + fileName);
            QMessageBox::information(this, "Успех", "Файл загружен на сервер");
        } else {
            log("Ошибка загрузки: " + QString(response));
            QMessageBox::warning(this, "Ошибка", QString(response));
        }
    } else {
        log("Таймаут загрузки файла");
        QMessageBox::warning(this, "Ошибка", "Таймаут загрузки файла");
    }
}
