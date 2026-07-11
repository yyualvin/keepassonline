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

#include <QObject>
#include <QtTest>

#include "core/Database.h"
#include "crypto/Hkdf.h"
#include "crypto/Random.h"
#include "crypto/SymmetricCipher.h"
#include "keys/CompositeKey.h"
#include "keys/PasswordKey.h"
#include "mock/MockWebAuthn.h"
#include "format/KeePass2.h"
#include "passkeyunlock/PasskeyUnlock.h"
#include "passkeyunlock/PasskeyUnlockRecord.h"

class TestPasskeyUnlock : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        PasskeyUnlock::setWebAuthnForTesting(&m_mockWebAuthn);
    }

    void cleanupTestCase()
    {
        PasskeyUnlock::setWebAuthnForTesting(nullptr);
    }

    void testRecordRoundTrip()
    {
        PasskeyUnlockRecord record;
        record.credentialId = QByteArray("credential");
        record.publicUuid = QUuid::createUuid();
        record.prfSalt = randomGen()->randomArray(PasskeyUnlockRecord::PRF_SALT_SIZE);
        record.hkdfSalt = randomGen()->randomArray(PasskeyUnlockRecord::HKDF_SALT_SIZE);
        record.hkdfInfo = QByteArray(PasskeyUnlock::HKDF_INFO_PREFIX) + record.publicUuid.toRfc4122()
                          + record.credentialId;
        record.aeadNonce = randomGen()->randomArray(PasskeyUnlockRecord::AEAD_NONCE_SIZE);
        record.wrappedKey = QByteArray("wrapped");

        const auto serialized = record.serialize();
        PasskeyUnlockRecord parsed;
        QVERIFY(parsed.deserialize(serialized));
        QCOMPARE(parsed.credentialId, record.credentialId);
        QCOMPARE(parsed.prfSalt, record.prfSalt);
        QCOMPARE(parsed.hkdfSalt, record.hkdfSalt);
        QCOMPARE(parsed.hkdfInfo, record.hkdfInfo);
        QCOMPARE(parsed.aeadAlgId, record.aeadAlgId);
        QCOMPARE(parsed.aeadNonce, record.aeadNonce);
        QCOMPARE(parsed.wrappedKey, record.wrappedKey);
        QCOMPARE(parsed.publicUuid, record.publicUuid);
    }

    void testMalformedRecord()
    {
        PasskeyUnlockRecord record;
        QVERIFY(!record.deserialize(QByteArray("bad")));
        QVERIFY(!record.deserialize(QByteArray("KPQU") + QByteArray(4, '\0')));
    }

    void testHkdfDeterminism()
    {
        const QByteArray secret(32, '\x01');
        const QByteArray salt(32, '\x02');
        const QByteArray info = QByteArray(PasskeyUnlock::HKDF_INFO_PREFIX) + QUuid::createUuid().toRfc4122();
        const auto first = Hkdf::sha256(secret, salt, info);
        const auto second = Hkdf::sha256(secret, salt, info);
        QCOMPARE(first, second);
        QCOMPARE(first.size(), 32);
    }

    void testWrapUnwrapAndAadBinding()
    {
        auto compositeKey = QSharedPointer<CompositeKey>::create();
        compositeKey->addKey(QSharedPointer<PasswordKey>::create("secret-password"));
        const QByteArray serializedKey = compositeKey->serialize();

        PasskeyUnlockRecord record;
        record.credentialId = QByteArray("credential");
        record.prfSalt = randomGen()->randomArray(PasskeyUnlockRecord::PRF_SALT_SIZE);
        record.hkdfSalt = randomGen()->randomArray(PasskeyUnlockRecord::HKDF_SALT_SIZE);
        record.publicUuid = QUuid::createUuid();
        record.hkdfInfo = QByteArray(PasskeyUnlock::HKDF_INFO_PREFIX) + record.publicUuid.toRfc4122()
                          + record.credentialId;
        record.aeadNonce = randomGen()->randomArray(PasskeyUnlockRecord::AEAD_NONCE_SIZE);

        const QByteArray wrapKey = Hkdf::sha256(m_mockWebAuthn.prfSecret, record.hkdfSalt, record.hkdfInfo);
        QVERIFY(!wrapKey.isEmpty());

        SymmetricCipher encrypt;
        QVERIFY(encrypt.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Encrypt, wrapKey, record.aeadNonce));
        record.wrappedKey = serializedKey;
        QVERIFY(encrypt.finish(record.wrappedKey));

        QByteArray recovered;
        SymmetricCipher decrypt;
        QVERIFY(decrypt.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, wrapKey, record.aeadNonce));
        recovered = record.wrappedKey;
        QVERIFY(decrypt.finish(recovered));
        QCOMPARE(recovered, serializedKey);

        const QByteArray wrongWrapKey =
            Hkdf::sha256(m_mockWebAuthn.prfSecret, record.hkdfSalt, record.hkdfInfo + QByteArray("tamper"));
        SymmetricCipher wrongKeyDecrypt;
        QVERIFY(
            wrongKeyDecrypt.init(SymmetricCipher::Aes256_GCM, SymmetricCipher::Decrypt, wrongWrapKey, record.aeadNonce));
        recovered = record.wrappedKey;
        QVERIFY(!wrongKeyDecrypt.finish(recovered));
    }

    void testEnableDisableRoundTrip()
    {
        MockWebAuthn mockWebAuthn;
        PasskeyUnlock::setWebAuthnForTesting(&mockWebAuthn);

        auto db = QSharedPointer<Database>::create();
        db->setFormatVersion(KeePass2::FILE_VERSION_4);
        auto key = QSharedPointer<CompositeKey>::create();
        key->addKey(QSharedPointer<PasswordKey>::create("database-password"));
        db->setKey(key, false, false, false);

        QString error;
        QVERIFY(PasskeyUnlock::enable(db, nullptr, &error));

        QVERIFY(PasskeyUnlock::isConfigured(db));

        QSharedPointer<CompositeKey> recovered;
        QVERIFY(PasskeyUnlock::unlock(db, nullptr, recovered, &error));
        QVERIFY(!recovered.isNull());
        QCOMPARE(recovered->serialize(), key->serialize());

        QVERIFY(PasskeyUnlock::disable(db, &error));
        QVERIFY(!PasskeyUnlock::isConfigured(db));
    }

private:
    MockWebAuthn m_mockWebAuthn;
};

QTEST_GUILESS_MAIN(TestPasskeyUnlock)
#include "TestPasskeyUnlock.moc"
