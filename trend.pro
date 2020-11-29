TEMPLATE = app # Тип приложения

CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += src/main.cpp

TARGET = trend # Название исполняемого файла

CONFIG(debug, debug|release)
{
    DEFINES -= NDEBUG
}
CONFIG(release, debug|release)
{
    DEFINES += NDEBUG
}

DISTFILES += \
    Readme.md \
    build.bat \
    CMakeLists.txt

