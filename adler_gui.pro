QT       += core gui network concurrent

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

TARGET = adler_gui
TEMPLATE = app

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    checksum_worker.cpp

HEADERS += \
    mainwindow.h \
    checksum_worker.h

FORMS += 

# Дополнительные флаги компиляции
QMAKE_CXXFLAGS += -Wall -Wextra -O2

# Пули для заголовочных файлов проекта
INCLUDEPATH += $$PWD
