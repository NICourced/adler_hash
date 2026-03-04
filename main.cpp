#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    
    // Устанавливаем организацию и имя приложения
    QApplication::setOrganizationName("Adler32Test");
    QApplication::setApplicationName("Adler32 GUI");
    
    MainWindow w;
    w.show();
    
    return a.exec();
}
