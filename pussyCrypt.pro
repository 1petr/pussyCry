TEMPLATE = app # Тип приложения

CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += src/main.cpp

TARGET = pussyCrypt # Название исполняемого файла

CONFIG(debug, debug|release)
{
    DEFINES -= NDEBUG
}
CONFIG(release, debug|release)
{
    DEFINES += NDEBUG
}

