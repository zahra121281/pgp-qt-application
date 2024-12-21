/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.12.8
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QPushButton *sendButton;
    QPushButton *sendImageButton;
    QPushButton *importKeyButton;
    QPushButton *exportKeyButton;
    QTextEdit *chatTextEdit;
    QLineEdit *inputLineEdit;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(800, 600);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        sendButton = new QPushButton(centralwidget);
        sendButton->setObjectName(QString::fromUtf8("sendButton"));
        sendButton->setGeometry(QRect(100, 220, 80, 25));
        sendImageButton = new QPushButton(centralwidget);
        sendImageButton->setObjectName(QString::fromUtf8("sendImageButton"));
        sendImageButton->setGeometry(QRect(200, 220, 101, 25));
        importKeyButton = new QPushButton(centralwidget);
        importKeyButton->setObjectName(QString::fromUtf8("importKeyButton"));
        importKeyButton->setGeometry(QRect(370, 220, 80, 25));
        exportKeyButton = new QPushButton(centralwidget);
        exportKeyButton->setObjectName(QString::fromUtf8("exportKeyButton"));
        exportKeyButton->setGeometry(QRect(490, 220, 80, 25));
        chatTextEdit = new QTextEdit(centralwidget);
        chatTextEdit->setObjectName(QString::fromUtf8("chatTextEdit"));
        chatTextEdit->setGeometry(QRect(90, 300, 601, 171));
        inputLineEdit = new QLineEdit(centralwidget);
        inputLineEdit->setObjectName(QString::fromUtf8("inputLineEdit"));
        inputLineEdit->setGeometry(QRect(100, 150, 511, 51));
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 800, 22));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", nullptr));
        sendButton->setText(QApplication::translate("MainWindow", "Send", nullptr));
        sendImageButton->setText(QApplication::translate("MainWindow", "send Image", nullptr));
        importKeyButton->setText(QApplication::translate("MainWindow", "import Key", nullptr));
        exportKeyButton->setText(QApplication::translate("MainWindow", "export Key", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
