#ifndef SERVER_H
#define SERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <gpgme.h>
#include <QByteArray>
#include <QTextStream>

class Server : public QObject
{
    Q_OBJECT
public:
    explicit Server(QObject *parent = nullptr);
    ~Server();

    bool startServer(quint16 port);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();

private:
    QString client_key_id;            // Server public key fingerprint
    QString server_key_id;              // Client private key fingerprint
    QByteArray keyBuffer; // Buffer to accumulate PGP key data
    bool isReceivingKey = false;
    QTcpServer *tcpServer;        // سرور TCP
    gpgme_ctx_t ctx;              // زمینه GPGME برای مدیریت عملیات رمزنگاری
    bool savePublicKey(const QByteArray &publicKeyData);  // ذخیره کلید عمومی
    void sendPublicKeyToClient(QTcpSocket *clientSocket);  // ارسال کلید عمومی به کلاینت
    bool initializeGPG();          // مقداردهی اولیه GPGME
    bool decryptMessage(const QByteArray &encryptedMessage, QByteArray &decryptedMessage);  // رمزگشایی پیام
    bool verifySignature(const QByteArray &message, const QByteArray &signature) ; 
    void sendResponse(QTcpSocket *socket, const QByteArray &response);  // ارسال پاسخ به کلاینت
    QByteArray extractSignatureFromEncryptedMessage(const QByteArray &receivedData);
    bool decryptAndVerify(const QByteArray &encryptedMessage, QByteArray &decryptedMessage);
};

#endif
