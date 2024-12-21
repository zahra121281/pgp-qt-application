QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# Enable debug symbols for development
CONFIG += debug

# Ensure debugging symbols are generated
QMAKE_CXXFLAGS_DEBUG += -g

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# Uncomment the following line to disable deprecated APIs up to a specific Qt version
# DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000

# Adding required Qt modules
QT += core gui widgets network

# Sources and headers
SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    mainwindow.h

FORMS += \
    mainwindow.ui

# Default rules for deployment
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

# Linking GPGME and dependencies
LIBS += -lgpgme -lgpg-error

# Adding include paths for GPGME
INCLUDEPATH += /usr/include
LIBS += -L/usr/lib
INCLUDEPATH += /usr/include /usr/include/x86_64-linux-gnu
