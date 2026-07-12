/*
 *  Copyright (C) 2025 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_TOUCHID_H
#define KEEPASSXC_TOUCHID_H

#include "QuickUnlockInterface.h"
#include <QHash>

class TouchID : public QuickUnlockInterface
{
public:
    bool isAvailable() const override;
    QString errorString() const override;

    bool hasKey(const QSharedPointer<Database>& db) const override;
    bool storeKey(const QSharedPointer<Database>& db, void* parentWindow, QString* error = nullptr) override;
    bool retrieveKey(const QSharedPointer<Database>& db,
                     QByteArray& serializedKey,
                     void* parentWindow,
                     QString* error = nullptr) override;
    void reset(const QSharedPointer<Database>& db) override;
    void clearSessionStorage(const QSharedPointer<Database>& db) override;

private:
    static bool isWatchAvailable();
    static bool isTouchIdAvailable();
    static bool isPasswordFallbackPossible();
    bool setSessionKey(const QUuid& dbUuid, const QByteArray& passwordKey);
    bool setSessionKey(const QUuid& dbUuid, const QByteArray& passwordKey, const bool ignoreTouchID);
    bool getSessionKey(const QUuid& dbUuid, QByteArray& passwordKey);
    bool hasSessionKey(const QUuid& dbUuid) const;
    void clearSessionKey(const QUuid& dbUuid);

    static void deleteKeyEntry(const QString& accountName);
    static QString databaseKeyName(const QUuid& dbUuid);

    QHash<QUuid, QByteArray> m_encryptedMasterKeys;
};

#endif // KEEPASSXC_TOUCHID_H
