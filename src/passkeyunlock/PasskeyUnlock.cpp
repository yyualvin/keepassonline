/*
 *  Copyright (C) 2026 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "PasskeyUnlock.h"

#include "PasskeyUnlockRecord.h"
#include "WebAuthnInterface.h"
#include "core/Database.h"
#include "crypto/Hkdf.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include "format/KeePass2.h"
#include "keys/CompositeKey.h"

#include <botan/mem_ops.h>

#include <QObject>

namespace
{
    WebAuthnInterface* g_testWebAuthn = nullptr;
} // namespace

void PasskeyUnlock::setWebAuthnForTesting(WebAuthnInterface* webAuthn)
{
    g_testWebAuthn = webAuthn;
}

WebAuthnInterface* PasskeyUnlock::webAuthn()
{
    if (g_testWebAuthn) {
        return g_testWebAuthn;
    }
    return getWebAuthn();
}

bool PasskeyUnlock::isAvailable()
{
    return webAuthn()->isAvailable();
}

bool PasskeyUnlock::readRecord(const QSharedPointer<Database>& db, PasskeyUnlockRecord& record)
{
    if (!db) {
        return false;
    }

    const auto data = db->publicCustomData().value(PUBLIC_CUSTOM_DATA_KEY).toByteArray();
    if (data.isEmpty()) {
        return false;
    }

    return record.deserialize(data);
}

bool PasskeyUnlock::writeRecord(const QSharedPointer<Database>& db, const PasskeyUnlockRecord& record)
{
    if (!db || !record.isValid()) {
        return false;
    }

    auto customData = db->publicCustomData();
    customData.insert(PUBLIC_CUSTOM_DATA_KEY, record.serialize());
    db->setPublicCustomData(customData);
    db->markAsModified();
    return true;
}

void PasskeyUnlock::removeRecord(const QSharedPointer<Database>& db)
{
    if (!db) {
        return;
    }

    auto customData = db->publicCustomData();
    if (!customData.contains(PUBLIC_CUSTOM_DATA_KEY)) {
        return;
    }

    customData.remove(PUBLIC_CUSTOM_DATA_KEY);
    db->setPublicCustomData(customData);
    db->markAsModified();
}

bool PasskeyUnlock::isConfigured(const QSharedPointer<Database>& db)
{
    if (!db || (db->formatVersion() & KeePass2::FILE_VERSION_CRITICAL_MASK) < KeePass2::FILE_VERSION_4) {
        return false;
    }

    PasskeyUnlockRecord record;
    return readRecord(db, record);
}

QByteArray PasskeyUnlock::buildHkdfInfo(const QUuid& publicUuid, const QByteArray& credentialId)
{
    QByteArray info = QByteArray(HKDF_INFO_PREFIX);
    info.append(publicUuid.toRfc4122());
    info.append(credentialId);
    return info;
}

bool PasskeyUnlock::deriveWrapKey(const QByteArray& prfOutput,
                                  const PasskeyUnlockRecord& record,
                                  QByteArray& wrapKey,
                                  QString* error)
{
    if (prfOutput.size() != 32) {
        if (error) {
            *error = QObject::tr("Invalid PRF output from authenticator.");
        }
        return false;
    }

    wrapKey = Hkdf::sha256(prfOutput, record.hkdfSalt, record.hkdfInfo);
    if (wrapKey.size() != SymmetricCipher::keySize(SymmetricCipher::Aes256_GCM)) {
        if (error) {
            *error = QObject::tr("Failed to derive wrapping key.");
        }
        return false;
    }

    return true;
}

bool PasskeyUnlock::wrapCompositeKey(const QByteArray& serializedKey,
                                     const QByteArray& wrapKey,
                                     const PasskeyUnlockRecord& record,
                                     QByteArray& wrapped,
                                     QString* error)
{
    wrapped = serializedKey;
    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, wrapKey, record.aeadNonce)) {
        if (error) {
            *error = QObject::tr("Failed to initialize encryption: %1").arg(cipher.errorString());
        }
        return false;
    }

    if (!cipher.finish(wrapped)) {
        if (error) {
            *error = QObject::tr("Failed to wrap database key: %1").arg(cipher.errorString());
        }
        return false;
    }

    return true;
}

bool PasskeyUnlock::unwrapCompositeKey(const QByteArray& wrapped,
                                       const QByteArray& wrapKey,
                                       const PasskeyUnlockRecord& record,
                                       QByteArray& serializedKey,
                                       QString* error)
{
    serializedKey = wrapped;
    SymmetricCipher cipher;
    if (!cipher.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, wrapKey, record.aeadNonce)) {
        if (error) {
            *error = QObject::tr("Failed to initialize decryption: %1").arg(cipher.errorString());
        }
        return false;
    }

    if (!cipher.finish(serializedKey)) {
        serializedKey.clear();
        if (error) {
            *error = QObject::tr("Wrapped database key could not be authenticated. The passkey quick unlock record "
                                 "may belong to a different database or is no longer valid.");
        }
        return false;
    }

    return true;
}

bool PasskeyUnlock::enable(const QSharedPointer<Database>& db, void* parentWindow, QString* error)
{
    if (!db || !db->key() || db->key()->isEmpty()) {
        if (error) {
            *error = QObject::tr("The database must be unlocked before enabling passkey quick unlock.");
        }
        return false;
    }

    if ((db->formatVersion() & KeePass2::FILE_VERSION_CRITICAL_MASK) < KeePass2::FILE_VERSION_4) {
        if (error) {
            *error = QObject::tr("Passkey quick unlock requires a KDBX4 database.");
        }
        return false;
    }

    if (!isAvailable()) {
        if (error) {
            *error = QObject::tr("WebAuthn with PRF support is not available on this system.");
        }
        return false;
    }

    const auto publicUuid = db->publicUuid();
    const auto userId = publicUuid.toRfc4122();

    PasskeyUnlockRecord record;
    record.publicUuid = publicUuid;
    record.prfSalt = randomGen()->randomArray(PasskeyUnlockRecord::PRF_SALT_SIZE);
    record.hkdfSalt = randomGen()->randomArray(PasskeyUnlockRecord::HKDF_SALT_SIZE);
    record.aeadAlgId = PasskeyUnlockRecord::AEAD_AES_256_GCM;
    record.aeadNonce = randomGen()->randomArray(PasskeyUnlockRecord::AEAD_NONCE_SIZE);

    QByteArray prfOutput;
    if (!webAuthn()->registerCredential(
            parentWindow, RP_ID, userId, record.prfSalt, record.credentialId, prfOutput, error)) {
        return false;
    }

    record.hkdfInfo = buildHkdfInfo(publicUuid, record.credentialId);

    QByteArray wrapKey;
    if (!deriveWrapKey(prfOutput, record, wrapKey, error)) {
        Botan::secure_scrub_memory(prfOutput.data(), prfOutput.size());
        return false;
    }
    Botan::secure_scrub_memory(prfOutput.data(), prfOutput.size());

    QByteArray serializedKey = db->key()->serialize();
    if (!wrapCompositeKey(serializedKey, wrapKey, record, record.wrappedKey, error)) {
        Botan::secure_scrub_memory(serializedKey.data(), serializedKey.size());
        Botan::secure_scrub_memory(wrapKey.data(), wrapKey.size());
        return false;
    }

    Botan::secure_scrub_memory(serializedKey.data(), serializedKey.size());
    Botan::secure_scrub_memory(wrapKey.data(), wrapKey.size());

    if (!writeRecord(db, record)) {
        if (error) {
            *error = QObject::tr("Failed to store passkey quick unlock record.");
        }
        return false;
    }

    return true;
}

bool PasskeyUnlock::disable(const QSharedPointer<Database>& db, QString* error)
{
    Q_UNUSED(error);
    if (!db) {
        return false;
    }

    if (!isConfigured(db)) {
        return true;
    }

    removeRecord(db);
    return true;
}

bool PasskeyUnlock::unlock(const QSharedPointer<Database>& db,
                           void* parentWindow,
                           QSharedPointer<CompositeKey>& compositeKey,
                           QString* error)
{
    compositeKey.clear();

    if (!db) {
        if (error) {
            *error = QObject::tr("No database loaded.");
        }
        return false;
    }

    PasskeyUnlockRecord record;
    if (!readRecord(db, record)) {
        if (error) {
            *error = QObject::tr("Passkey quick unlock is not configured for this database.");
        }
        return false;
    }

    if (record.publicUuid != db->publicUuid()) {
        if (error) {
            *error = QObject::tr("The stored passkey quick unlock record belongs to a different database.");
        }
        return false;
    }

    if (!isAvailable()) {
        if (error) {
            *error = QObject::tr("WebAuthn with PRF support is not available on this system.");
        }
        return false;
    }

    QByteArray prfOutput;
    if (!webAuthn()->evaluatePrf(parentWindow, RP_ID, record.credentialId, record.prfSalt, prfOutput, error)) {
        return false;
    }

    QByteArray wrapKey;
    if (!deriveWrapKey(prfOutput, record, wrapKey, error)) {
        Botan::secure_scrub_memory(prfOutput.data(), prfOutput.size());
        return false;
    }
    Botan::secure_scrub_memory(prfOutput.data(), prfOutput.size());

    QByteArray serializedKey;
    if (!unwrapCompositeKey(record.wrappedKey, wrapKey, record, serializedKey, error)) {
        Botan::secure_scrub_memory(wrapKey.data(), wrapKey.size());
        return false;
    }
    Botan::secure_scrub_memory(wrapKey.data(), wrapKey.size());

    compositeKey = QSharedPointer<CompositeKey>::create();
    compositeKey->setRawKey(serializedKey);
    Botan::secure_scrub_memory(serializedKey.data(), serializedKey.size());

    if (compositeKey->isEmpty()) {
        compositeKey.clear();
        if (error) {
            *error = QObject::tr("The stored passkey quick unlock record is malformed.");
        }
        return false;
    }

    return true;
}
