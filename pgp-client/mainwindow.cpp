#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QBuffer>
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include <gpgme.h>
#include <QImageReader>
#include <QAbstractSocket>
#include <QTcpSocket>


void MainWindow::onConnected()
{
    ui->chatTextEdit->append("Connected to server.");
}
void MainWindow::onDisconnected()
{
    ui->chatTextEdit->append("Disconnected from server.");
}

void MainWindow::onErrorOccurred(QAbstractSocket::SocketError socketError)
{
    ui->chatTextEdit->append("Error: " + tcpSocket->errorString());
}



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), ctx(nullptr), tcpSocket(new QTcpSocket(this))
{
    ui->setupUi(this);

    // Connect signals to slots
    connect(ui->sendButton, &QPushButton::clicked, this, &MainWindow::onSendButtonClicked);
    connect(ui->sendImageButton, &QPushButton::clicked, this, &MainWindow::onSendImageButtonClicked);
    connect(ui->importKeyButton, &QPushButton::clicked, this, &MainWindow::onImportKeyButtonClicked);
    connect(ui->exportKeyButton, &QPushButton::clicked, this, &MainWindow::onExportKeyButtonClicked);

    connect(tcpSocket, &QTcpSocket::connected, this, &MainWindow::onConnected);
    connect(tcpSocket, &QTcpSocket::readyRead, this, &MainWindow::onReadyRead);
    connect(tcpSocket, &QTcpSocket::disconnected, this, &MainWindow::onDisconnected);
    connect(tcpSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error), this, &MainWindow::onErrorOccurred);

    if (!initializeGPG()) {
        qCritical() << "Failed to initialize GPGME.";
    }

    tcpSocket->connectToHost("127.0.0.1", 12345);
}

MainWindow::~MainWindow()
{
    gpgme_release(ctx);
    delete ui;
}

bool MainWindow::initializeGPG()
{
    const char *version = gpgme_check_version(nullptr);
    if (!version) {
        qCritical() << "Failed to initialize GPGME.";
        return false;
    }
    setlocale(LC_ALL, "");
    if (gpgme_new(&ctx) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to create GPGME context.";
        return false;
    }
    if (gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to set GPGME protocol.";
        return false;
    }
    return true;
}

bool MainWindow::encryptAndSignMessage(const std::string &message, const std::string &recipientKey, std::string &encryptedSignedMessage)
{
    gpgme_data_t inData, outData;
    gpgme_key_t recipient = nullptr;
    gpgme_key_t signer = nullptr;

    // Create input data from the message
    if (gpgme_data_new_from_mem(&inData, message.c_str(), message.size(), 0) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to create input data.";
        return false;
    }

    // Create output data buffer
    if (gpgme_data_new(&outData) != GPG_ERR_NO_ERROR) {
        gpgme_data_release(inData);
        qCritical() << "Failed to create output data.";
        return false;
    }

    // Get the recipient's public key (for encryption)
    if (gpgme_get_key(ctx, recipientKey.c_str(), &recipient, 0) != GPG_ERR_NO_ERROR) {
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        qCritical() << "Failed to get recipient key.";
        return false;
    }

    // Get the signing key (your private key)
    if (gpgme_get_key(ctx, signing_key_id.toStdString().c_str(), &signer, 1) != GPG_ERR_NO_ERROR) {
        gpgme_key_unref(recipient);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        qCritical() << "Failed to get signing key.";
        return false;
    }

    // Add signing key to context
    if (gpgme_signers_add(ctx, signer) != GPG_ERR_NO_ERROR) {
        gpgme_key_unref(recipient);
        gpgme_key_unref(signer);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        qCritical() << "Failed to add signing key to context.";
        return false;
    }

    // Encrypt and sign the message
    gpgme_key_t recipients[2] = {recipient, nullptr};  // Add recipients
    if (gpgme_op_encrypt_sign(ctx, recipients, GPGME_ENCRYPT_ALWAYS_TRUST, inData, outData) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to encrypt and sign.";
        gpgme_key_unref(recipient);
        gpgme_key_unref(signer);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        return false;
    }

    // Get the encrypted and signed message
    size_t outSize;
    char *outBuffer = gpgme_data_release_and_get_mem(outData, &outSize);
    if (!outBuffer) {
        gpgme_key_unref(recipient);
        gpgme_key_unref(signer);
        gpgme_data_release(inData);
        qCritical() << "Failed to get encrypted and signed message.";
        return false;
    }

    // Assign the result to the output variable
    encryptedSignedMessage.assign(outBuffer, outSize);

    // Free allocated resources
    gpgme_free(outBuffer);
    gpgme_key_unref(recipient);
    gpgme_key_unref(signer);
    gpgme_data_release(inData);

    return true;
}

void MainWindow::onSendButtonClicked()
{
    std::string message = ui->inputLineEdit->text().toStdString();
    if (message.empty()) {
        qWarning() << "Message is empty!";
        return;
    }

    std::string encryptedSignedMessage;
    if (encryptAndSignMessage(message, recipient_key_id.toStdString(), encryptedSignedMessage)) {
        sendMessageToServer(QByteArray::fromStdString(encryptedSignedMessage));
        ui->chatTextEdit->append("Encrypted and Signed Message Sent!");
    } else {
        qWarning() << "Failed to encrypt and sign message.";
    }

    ui->inputLineEdit->clear();
}

void MainWindow::onSendImageButtonClicked()
{
    QString imagePath = QFileDialog::getOpenFileName(this, "Select Image", "", "Images (*.png *.jpg *.jpeg *.bmp *.gif)");
    if (imagePath.isEmpty()) {
        qWarning() << "No image selected.";
        return;
    }

    QByteArray imageData;
    QImageReader reader(imagePath);
    QImage image = reader.read();
    if (image.isNull()) {
        qWarning() << "Failed to read image.";
        return;
    }

    QBuffer buffer(&imageData);
    buffer.open(QIODevice::WriteOnly);
    if (!image.save(&buffer, "PNG")) {
        qWarning() << "Failed to save image to QByteArray.";
        return;
    }

    std::string encryptedSignedMessage;
    if (encryptAndSignMessage(std::string(imageData.constData(), imageData.size()), recipient_key_id.toStdString(), encryptedSignedMessage)) {
        sendMessageToServer(QByteArray::fromStdString(encryptedSignedMessage));
        ui->chatTextEdit->append("Encrypted and Signed Image Sent!");
    } else {
        qWarning() << "Failed to encrypt and sign image.";
    }
}

void MainWindow::onImportKeyButtonClicked()
{
    if (QMessageBox::question(this, "Import Key", "Generate a new key or import from file?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
        if (generateKeyPair()) {
            ui->chatTextEdit->append("Generated new key pair.");
        } else {
            ui->chatTextEdit->append("Failed to generate key pair.");
        }
    } else {
        QString pubFile = QFileDialog::getOpenFileName(this, "Select Public Key", "", "*.asc");
        QString privFile = QFileDialog::getOpenFileName(this, "Select Private Key", "", "*.asc");

        if (pubFile.isEmpty() || privFile.isEmpty()) {
            ui->chatTextEdit->append("Key import cancelled.");
            return;
        }

        if (importKeyPair(pubFile, privFile)) {
            ui->chatTextEdit->append("Imported key pair.");
        } else {
            ui->chatTextEdit->append("Failed to import keys.");
        }
    }
}

bool MainWindow::importKeyPair(const QString &pubFile, const QString &privFile) {
    gpgme_data_t pubData;
    gpgme_error_t err;

    // باز کردن و خواندن فایل کلید عمومی
    QFile pubKeyFile(pubFile);
    if (!pubKeyFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Failed to open public key file:" << pubFile;
        return false;
    }

    QByteArray pubKeyData = pubKeyFile.readAll();
    pubKeyFile.close();

    // تبدیل داده به gpgme_data_t
    err = gpgme_data_new_from_mem(&pubData, pubKeyData.constData(), pubKeyData.size(), 0);
    if (err != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to create GPGME data from public key:" << gpgme_strerror(err);
        return false;
    }

    // وارد کردن کلید عمومی
    err = gpgme_op_import(ctx, pubData);
    gpgme_data_release(pubData);
    if (err != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to import public key:" << gpgme_strerror(err);
        return false;
    }

    // باز کردن و خواندن فایل کلید خصوصی
    QFile privKeyFile(privFile);
    if (!privKeyFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Failed to open private key file:" << privFile;
        return false;
    }

    QByteArray privKeyData = privKeyFile.readAll();
    privKeyFile.close();

    gpgme_data_t privData;
    err = gpgme_data_new_from_mem(&privData, privKeyData.constData(), privKeyData.size(), 0);
    if (err != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to create GPGME data from private key:" << gpgme_strerror(err);
        return false;
    }

    // وارد کردن کلید خصوصی
    err = gpgme_op_import(ctx, privData);
    gpgme_data_release(privData);
    if (err != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to import private key:" << gpgme_strerror(err);
        return false;
    }

    qDebug() << "Keys imported successfully!";
    return true;
}

void MainWindow::onExportKeyButtonClicked()
{
    sendPublicKeyToServer();
}

bool MainWindow::generateKeyPair()
{
    const char *params =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 2048\n"
        "Name-Real: Example User\n"
        "Name-Email: example@example.com\n"
        "Expire-Date: 0\n"
        "</GnupgKeyParms>";

    if (gpgme_op_genkey(ctx, params, nullptr, nullptr) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to generate key pair.";
        return false;
    }
    gpgme_genkey_result_t result = gpgme_op_genkey_result(ctx);
    if (!result || !result->fpr) {
        qWarning() << "Failed to retrieve fingerprint of generated key.";
        return false;
    }
    signing_key_id = QString::fromUtf8(result->fpr);
    //qDebug() << "Generated key pair with fingerprint (signing_key_id):" << signing_key_id;
    return true;
}

void MainWindow::sendPublicKeyToServer()
{
    // فعال کردن حالت ASCII-armored

    // ایجاد داده برای کلید عمومی
    gpgme_data_t keyData;
    if (gpgme_data_new(&keyData) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to prepare public key.";
        return;
    }

    gpgme_set_armor(ctx, 1);
    // صادر کردن کلید عمومی
    if (gpgme_op_export(ctx, signing_key_id.toStdString().c_str(), 0, keyData) != GPG_ERR_NO_ERROR) {
        qCritical() << "Failed to export public key.";
        gpgme_data_release(keyData);
        return;
    }

    size_t outSize;
    char *outBuffer = gpgme_data_release_and_get_mem(keyData, &outSize);
    if (!outBuffer || outSize == 0) {
        qWarning() << "Failed to retrieve exported public key data.";
        tcpSocket->write("ERROR: Failed to retrieve public key data.");
        tcpSocket->flush();
        return;
    }

    QByteArray publicKey(outBuffer, outSize);
    gpgme_free(outBuffer);

    tcpSocket->write(publicKey); // ارسال کلید عمومی
    tcpSocket->flush();

    qDebug() << "Public key sent to server.";
}

void MainWindow::sendMessageToServer(const QByteArray &message)
{
    if (tcpSocket->state() == QTcpSocket::ConnectedState) {
        tcpSocket->write(message);
    } else {
        qWarning() << "Not connected to server.";
    }
}

bool MainWindow::savePublicKeyToFile(const QByteArray &keyData, const QString &fileName) {
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        qCritical() << "Failed to open file for writing:" << fileName;
        return false ; 
    }

    file.write(keyData);
    file.close();
    qDebug() << "Public key saved to file:" << fileName;
    return true ; 
}


void MainWindow::onReadyRead()
{
    QByteArray receivedData = tcpSocket->readAll(); 
    
    qDebug() << "Received data (Hex):" << receivedData.left(100);
    if (receivedData.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----") &&
        receivedData.contains("-----END PGP PUBLIC KEY BLOCK-----")) {
        ui->chatTextEdit->append("Received public key from server.");
        qDebug() << "-----BEGIN PGP PUBLIC KEY BLOCK-----" ; 
        // ذخیره و وارد کردن کلید عمومی
        QString filePath = "server_public_key.asc";
        if (savePublicKeyToFile(receivedData, filePath)) {
            ui->chatTextEdit->append("Server public key saved to: " + filePath);

            // وارد کردن کلید عمومی به حلقه کلیدها
            if (importPublicKeyFromData(receivedData)) {
                ui->chatTextEdit->append("Server public key imported successfully!");
                ui->chatTextEdit->append("Server key ID (Fingerprint): " + recipient_key_id);
            } else {
                ui->chatTextEdit->append("Failed to import server public key.");
            }
        } else {
            ui->chatTextEdit->append("Failed to save server public key.");
        }
    } else {
        // پیام رمزگذاری‌شده یا پیام معمولی
        qDebug() << "Received data (length):" << receivedData.size();

        if (!receivedData.isEmpty()) {
            // پیام معمولی را مستقیماً نمایش می‌دهد
            ui->chatTextEdit->append("Received message: " + QString(receivedData));
        } else {
            qWarning() << "Received empty message.";
            ui->chatTextEdit->append("Received an empty message.");
        }
    }
}


bool MainWindow::importPublicKeyFromData(const QByteArray &publicKeyData)
{
    gpgme_data_t keyData;
    gpgme_error_t err;

    // تبدیل داده کلید عمومی به gpgme_data_t
    err = gpgme_data_new_from_mem(&keyData, publicKeyData.constData(), publicKeyData.size(), 0);
    if (err) {
        qWarning() << "Failed to create GPGME data from public key:" << gpgme_strerror(err);
        return false;
    }

    // وارد کردن کلید عمومی به حلقه کلیدها
    err = gpgme_op_import(ctx, keyData);
    gpgme_data_release(keyData);

    if (err) {
        qWarning() << "Failed to import public key:" << gpgme_strerror(err);
        return false;
    }

    // شروع لیست کلیدها
    err = gpgme_op_keylist_start(ctx, nullptr, 0);
    if (err) {
        qWarning() << "Failed to start key listing:" << gpgme_strerror(err);
        return false;
    }

    // استخراج اولین کلید (کلید عمومی وارد شده)
    gpgme_key_t key;
    err = gpgme_op_keylist_next(ctx, &key);
    if (err) {
        qWarning() << "Failed to retrieve key from keyring:" << gpgme_strerror(err);
        return false;
    }

    // ذخیره اثر انگشت کلید (Fingerprint)
    if (key->subkeys && key->subkeys->fpr) {
        recipient_key_id = QString::fromUtf8(key->subkeys->fpr);
        qDebug() << "Server public key fingerprint (recipient_key_id):" << recipient_key_id;
    } else {
        qWarning() << "No fingerprint found for the imported key.";
    }

    // آزاد کردن کلید
    gpgme_key_unref(key);

    return true;
}
