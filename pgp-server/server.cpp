#include "server.h"
#include <QTcpSocket>
#include <QTextStream>
#include <QFile>
#include <QDebug>
#include <iostream>

Server::Server(QObject *parent) : QObject(parent), tcpServer(nullptr), ctx(nullptr)
{
}

Server::~Server()
{
    gpgme_release(ctx);
}

bool Server::startServer(quint16 port)
{
    // مقداردهی اولیه GPGME
    if (!initializeGPG()) {
        qCritical() << "Failed to initialize GPGME.";
        return false;
    }

    // ایجاد نمونه QTcpServer
    tcpServer = new QTcpServer(this);
    if (!tcpServer->listen(QHostAddress::Any, port)) {
        qCritical() << "Server could not start!";
        return false;
    }

    qDebug() << "Server started on port" << port;

    // اتصال سیگنال newConnection به اسلات onNewConnection
    connect(tcpServer, &QTcpServer::newConnection, this, &Server::onNewConnection);
    return true;
}

void Server::onNewConnection()
{
    QTcpSocket *clientSocket = tcpServer->nextPendingConnection();

    connect(clientSocket, &QTcpSocket::readyRead, this, &Server::onReadyRead);
    connect(clientSocket, &QTcpSocket::disconnected, this, &Server::onDisconnected);

    qDebug() << "New client connected.";

    sendPublicKeyToClient(clientSocket);
}

bool Server::savePublicKey(const QByteArray &publicKeyData)
{
    // Save the public key to a file
    QString filePath = "received_client_public_key.asc";
    QFile keyFile(filePath);
    if (!keyFile.open(QIODevice::WriteOnly)) {
        qWarning() << "Failed to open file to save public key.";
        return false;
    }
    keyFile.write(publicKeyData);
    keyFile.close();
    qDebug() << "Public key saved to file:" << filePath;

    // Import the public key into the keyring
    gpgme_data_t keyData;
    gpgme_error_t err = gpgme_data_new_from_mem(&keyData, publicKeyData.constData(), publicKeyData.size(), 0);
    if (err) {
        qWarning() << "Failed to create GPGME data from public key:" << gpgme_strerror(err);
        return false;
    }

    err = gpgme_op_import(ctx, keyData);
    gpgme_data_release(keyData);

    if (err) {
        qWarning() << "Failed to import public key:" << gpgme_strerror(err);
        return false;
    }

    // Retrieve the import result to get the fingerprint
    gpgme_import_result_t importResult = gpgme_op_import_result(ctx);
    if (!importResult || !importResult->imports || !importResult->imports->fpr) {
        qWarning() << "Failed to retrieve fingerprint of the imported key.";
        return false;
    }

    // Save the fingerprint of the imported key
    client_key_id = QString::fromUtf8(importResult->imports->fpr);
    qDebug() << "Public key imported successfully. Fingerprint:" << client_key_id;
    return true;
}


void Server::onReadyRead()
{
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket *>(sender());
    if (!clientSocket) return;

    QByteArray receivedData = clientSocket->readAll();
    

    // If data starts with the public key marker, initialize the buffer
    if (receivedData.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
        qDebug() << "Start receiving a public key.";
        keyBuffer.clear(); // Clear the buffer for a new key
        isReceivingKey = true; // Set the flag to indicate key reception
    }

    // If receiving key, accumulate data into the buffer
    if (isReceivingKey) {
        keyBuffer.append(receivedData);

        // Check if the key reception is complete
        if (keyBuffer.contains("-----END PGP PUBLIC KEY BLOCK-----")) {
            qDebug() << "Received a complete public key.";
            isReceivingKey = false; // Reset the flag

            // Save and process the public key
            if (savePublicKey(keyBuffer)) {
                qDebug() << "Public key saved and imported successfully.";
                sendResponse(clientSocket, "Public key received successfully.");
            } else {
                qWarning() << "Failed to save or import public key.";
                sendResponse(clientSocket, "Failed to process public key.");
            }

            keyBuffer.clear(); // Clear the buffer after processing the key
        }

        return; // Exit since the data is part of the key
    }

    // If not receiving a key, process as encrypted message
    qDebug() << "Processing encrypted message.";
    
    QByteArray decryptedMessage;

    qDebug() << "Encrypted message received: " << receivedData;

    // Perform decryption and signature verification in one step
    if (decryptAndVerify(receivedData, decryptedMessage)) {
        qDebug() << "Decrypted message: " << decryptedMessage;
        sendResponse(clientSocket, "Message received and verified!");
    } else {
        qWarning() << "Failed to decrypt or verify signature!";
        sendResponse(clientSocket, "Invalid message or signature!");
    }
}

bool Server::decryptAndVerify(const QByteArray &encryptedMessage, QByteArray &decryptedMessage)
{
    gpgme_data_t inData, outData;
    gpgme_error_t err;
    gpgme_verify_result_t verifyResult;

    // Ensure the server's private key and the client's public key are available
    gpgme_key_t decryptionKey = nullptr, verificationKey = nullptr;

    // Load the server's private key for decryption
    err = gpgme_get_key(ctx, server_key_id.toStdString().c_str(), &decryptionKey, 1); // 1 = private key
    if (err != GPG_ERR_NO_ERROR) {
        qWarning() << "Failed to load server's private key for decryption:" << gpgme_strerror(err);
        return false;
    }

    // Load the client's public key for signature verification
    err = gpgme_get_key(ctx, client_key_id.toStdString().c_str(), &verificationKey, 0); // 0 = public key
    if (err != GPG_ERR_NO_ERROR) {
        qWarning() << "Failed to load client's public key for signature verification:" << gpgme_strerror(err);
        gpgme_key_unref(decryptionKey);
        return false;
    }

    // Create GPGME input data
    err = gpgme_data_new_from_mem(&inData, encryptedMessage.constData(), encryptedMessage.size(), 0);
    if (err) {
        qWarning() << "Failed to create input data for GPGME:" << gpgme_strerror(err);
        gpgme_key_unref(decryptionKey);
        gpgme_key_unref(verificationKey);
        return false;
    }

    // Create GPGME output data
    err = gpgme_data_new(&outData);
    if (err) {
        qWarning() << "Failed to create output data for GPGME:" << gpgme_strerror(err);
        gpgme_data_release(inData);
        gpgme_key_unref(decryptionKey);
        gpgme_key_unref(verificationKey);
        return false;
    }

    // Decrypt and verify
    err = gpgme_op_decrypt_verify(ctx, inData, outData);
    if (err) {
        qWarning() << "Failed to decrypt and verify signature:" << gpgme_strerror(err);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        gpgme_key_unref(decryptionKey);
        gpgme_key_unref(verificationKey);
        return false;
    }

    // Extract decrypted message
    size_t outSize;
    const char *outBuffer = gpgme_data_release_and_get_mem(outData, &outSize);
    if (!outBuffer || outSize == 0) {
        qWarning() << "Failed to extract decrypted message!";
        gpgme_data_release(inData);
        gpgme_key_unref(decryptionKey);
        gpgme_key_unref(verificationKey);
        return false;
    }
    decryptedMessage = QByteArray(outBuffer, outSize);
    gpgme_free((void *)outBuffer);

    // Verify signature result
    verifyResult = gpgme_op_verify_result(ctx);
    if (!verifyResult || !verifyResult->signatures || verifyResult->signatures->status != GPG_ERR_NO_ERROR) {
        qWarning() << "Signature verification failed!";
        gpgme_data_release(inData);
        gpgme_key_unref(decryptionKey);
        gpgme_key_unref(verificationKey);
        return false;
    }

    qDebug() << "Signature verified successfully.";

    gpgme_data_release(inData);
    gpgme_key_unref(decryptionKey);
    gpgme_key_unref(verificationKey);
    return true;
}


void Server::onDisconnected()
{
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket *>(sender());
    clientSocket->deleteLater();
}

bool Server::initializeGPG()
{
    gpgme_error_t err;

    // بررسی نسخه GPGME
    if (!gpgme_check_version(nullptr)) {
        qCritical() << "Failed to check GPGME version.";
        return false;
    }

    // تنظیمات محلی (Locale)
    setlocale(LC_ALL, "");

    // مقداردهی زمینه GPGME
    err = gpgme_new(&ctx);
    if (err) {
        qCritical() << "Failed to initialize GPGME context:" << gpgme_strerror(err);
        return false;
    }

    // تنظیم موتور GPGME برای OpenPGP
    err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, nullptr, nullptr);
    if (err) {
        qCritical() << "Failed to set GPGME engine info:" << gpgme_strerror(err);
        gpgme_release(ctx);
        ctx = nullptr;
        return false;
    }

    // تنظیم پروتکل GPGME
    gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

    return true;
}

bool Server::decryptMessage(const QByteArray &encryptedMessage, QByteArray &decryptedMessage)
{
    gpgme_data_t inData, outData;
    gpgme_error_t err;

    err = gpgme_data_new_from_mem(&inData, encryptedMessage.constData(), encryptedMessage.size(), 0);
    if (err) {
        qWarning() << "Failed to create GPGME input data:" << gpgme_strerror(err);
        return false;
    }

    // Create GPGME output data for decrypted message
    err = gpgme_data_new(&outData);
    if (err) {
        qWarning() << "Failed to create GPGME output data:" << gpgme_strerror(err);
        gpgme_data_release(inData);
        return false;
    }

    // Ensure the private key corresponding to server_key_id is available
    gpgme_key_t serverKey = nullptr;
    err = gpgme_get_key(ctx, server_key_id.toUtf8().constData(), &serverKey, 1); // 1 for secret key (private key)
    if (err) {
        qWarning() << "Failed to retrieve private key for decryption (key ID: " << server_key_id << "): " << gpgme_strerror(err);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        return false;
    }
    gpgme_key_unref(serverKey); // We only need to verify its presence, not retain it

    // Decrypt the message
    err = gpgme_op_decrypt(ctx, inData, outData);
    if (err) {
        qWarning() << "Failed to decrypt message:" << gpgme_strerror(err);
        gpgme_data_release(inData);
        gpgme_data_release(outData);
        return false;
    }

    // Extract decrypted message data
    size_t outSize;
    const char *outBuffer = gpgme_data_release_and_get_mem(outData, &outSize);

    if (outBuffer && outSize > 0) {
        decryptedMessage = QByteArray(outBuffer, outSize);
        gpgme_free((void *)outBuffer); // Free allocated memory
    } else {
        qWarning() << "Failed to extract decrypted message.";
        gpgme_data_release(inData);
        return false;
    }

    gpgme_data_release(inData);
    return true;
}


void Server::sendResponse(QTcpSocket *socket, const QByteArray &response)
{
    socket->write(response);
    socket->flush();
}

void Server::sendPublicKeyToClient(QTcpSocket *clientSocket)
{
    gpgme_error_t err;
    gpgme_genkey_result_t genResult;
    
    const char *keyParams =
        "<GnupgKeyParms format=\"internal\">\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 2048\n"
        "Name-Real: Server Key\n"
        "Name-Email: server@example.com\n"
        "Expire-Date: 0\n"
        "</GnupgKeyParms>";

    // تولید کلید
    err = gpgme_op_genkey(ctx, keyParams, nullptr, nullptr);
    if (err) {
        qWarning() << "Failed to generate key pair:" << gpgme_strerror(err);
        clientSocket->write("ERROR: Failed to generate key pair.");
        clientSocket->flush();
        return;
    }

    genResult = gpgme_op_genkey_result(ctx);
    if (!genResult || !genResult->fpr) {
        qWarning() << "Failed to retrieve generated key fingerprint.";
        clientSocket->write("ERROR: Failed to retrieve key fingerprint.");
        clientSocket->flush();
        return;
    }
    
    server_key_id = QString::fromUtf8(genResult->fpr);

    gpgme_data_t publicKeyData;
    err = gpgme_data_new(&publicKeyData);
    if (err) {
        qWarning() << "Failed to create GPGME data object:" << gpgme_strerror(err);
        clientSocket->write("ERROR: Failed to prepare key export.");
        clientSocket->flush();
        return;
    }

    // فعال کردن حالت ASCII-armored
    gpgme_set_armor(ctx, 1);

    // صادر کردن کلید عمومی به صورت ASCII-armored
    err = gpgme_op_export(ctx, server_key_id.toStdString().c_str(), 0, publicKeyData);
    if (err) {
        qWarning() << "Failed to export public key:" << gpgme_strerror(err);
        gpgme_data_release(publicKeyData);
        clientSocket->write("ERROR: Failed to export public key.");
        clientSocket->flush();
        return;
    }

    size_t outSize;
    char *outBuffer = gpgme_data_release_and_get_mem(publicKeyData, &outSize);
    if (!outBuffer || outSize == 0) {
        qWarning() << "Failed to retrieve exported public key data.";
        clientSocket->write("ERROR: Failed to retrieve public key data.");
        clientSocket->flush();
        return;
    }

    QByteArray publicKey(outBuffer, outSize);
    gpgme_free(outBuffer);

    clientSocket->write(publicKey); // ارسال کلید عمومی
    clientSocket->flush();

    qDebug() << "Public key sent to client.";
}
