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

#ifndef KEEPASSX_PASSKEY_UNLOCK_H
#define KEEPASSX_PASSKEY_UNLOCK_H

#include <QSharedPointer>
#include <QString>

class CompositeKey;
class Database;
class PasskeyUnlockRecord;
class WebAuthnInterface;

class PasskeyUnlock
{
public:
    static constexpr const char* PUBLIC_CUSTOM_DATA_KEY = "KPXC_PASSKEY_QUICKUNLOCK";
    static constexpr const char* RP_ID = "org.keepassxc.app";
    static constexpr const char* HKDF_INFO_PREFIX = "KeePassXC Passkey Quick Unlock v1";

    static bool isAvailable();
    static bool isConfigured(const QSharedPointer<Database>& db);
    static bool enable(const QSharedPointer<Database>& db, void* parentWindow, QString* error = nullptr);
    static bool disable(const QSharedPointer<Database>& db, QString* error = nullptr);
    static bool unlock(const QSharedPointer<Database>& db,
                       void* parentWindow,
                       QSharedPointer<CompositeKey>& compositeKey,
                       QString* error = nullptr);

    static bool readRecord(const QSharedPointer<Database>& db, PasskeyUnlockRecord& record);
    static bool writeRecord(const QSharedPointer<Database>& db, const PasskeyUnlockRecord& record);
    static void removeRecord(const QSharedPointer<Database>& db);

    static void setWebAuthnForTesting(WebAuthnInterface* webAuthn);

private:
    static QByteArray buildHkdfInfo(const QUuid& publicUuid, const QByteArray& credentialId);
    static bool deriveWrapKey(const QByteArray& prfOutput,
                              const PasskeyUnlockRecord& record,
                              QByteArray& wrapKey,
                              QString* error);
    static bool wrapCompositeKey(const QByteArray& serializedKey,
                                 const QByteArray& wrapKey,
                                 const PasskeyUnlockRecord& record,
                                 QByteArray& wrapped,
                                 QString* error);
    static bool unwrapCompositeKey(const QByteArray& wrapped,
                                   const QByteArray& wrapKey,
                                   const PasskeyUnlockRecord& record,
                                   QByteArray& serializedKey,
                                   QString* error);

    static WebAuthnInterface* webAuthn();
};

#endif // KEEPASSX_PASSKEY_UNLOCK_H
