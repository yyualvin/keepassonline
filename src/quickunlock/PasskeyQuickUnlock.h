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

#ifndef KEEPASSXC_PASSKEYQUICKUNLOCK_H
#define KEEPASSXC_PASSKEYQUICKUNLOCK_H

#include "QuickUnlockInterface.h"

class PasskeyQuickUnlock : public QuickUnlockInterface
{
public:
    bool isAvailable() const override;
    QString errorString() const override;
    bool needsSaveAfterStore() const override;

    bool hasKey(const QSharedPointer<Database>& db) const override;
    bool storeKey(const QSharedPointer<Database>& db, void* parentWindow, QString* error = nullptr) override;
    bool retrieveKey(const QSharedPointer<Database>& db,
                     QByteArray& serializedKey,
                     void* parentWindow,
                     QString* error = nullptr) override;
    void reset(const QSharedPointer<Database>& db) override;

private:
    QString m_error;
};

#endif // KEEPASSXC_PASSKEYQUICKUNLOCK_H
