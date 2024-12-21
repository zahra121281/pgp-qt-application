#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QTcpSocket>
#include <QMessageBox>
#include <gpgme.h>
#include <QDebug>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Slot functions for UI interactions
    void onSendButtonClicked();
    void onSendImageButtonClicked();
    void onImportKeyButtonClicked();
    void onExportKeyButtonClicked();
    void onConnected();
    void onReadyRead();
    void onDisconnected();
    void onErrorOccurred(QAbstractSocket::SocketError socketError);

private:
    Ui::MainWindow *ui;
    gpgme_ctx_t ctx;                     // GPG context
    QTcpSocket *tcpSocket;               // Socket for server communication

    QString recipient_key_id;            // Server public key fingerprint
    QString signing_key_id;              // Client private key fingerprint

    // GPG initialization
    bool initializeGPG();

    // Key management
    bool generateKeyPair();
    bool importKeyPair(const QString &publicKeyFile, const QString &privateKeyFile);
    bool importPublicKey(const std::string &keyFile);
    bool exportPublicKey(const std::string &keyFile);
   
    bool importPublicKeyFromData(const QByteArray &publicKeyData);
    bool encryptAndSignMessage(const std::string &message, const std::string &recipientKey, std::string &encryptedSignedMessage); 
    // Message processing
    bool signEncryptMessage(const std::string &message, const std::string &recipientKey, std::string &encryptedMessage);
    bool decryptVerifyMessage(const QByteArray &encryptedData, QByteArray &decryptedMessage);
    bool processImage(const QString &imagePath, QByteArray &encryptedImageData);

    // Server communication
    void sendPublicKeyToServer();
    void sendMessageToServer(const QByteArray &message);
    bool savePublicKeyToFile(const QByteArray &keyData, const QString &fileName);
};

#endif // MAINWINDOW_H
