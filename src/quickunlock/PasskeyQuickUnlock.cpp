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

#include "PasskeyQuickUnlock.h"

#include "passkeyunlock/PasskeyUnlock.h"

#include <QObject>

bool PasskeyQuickUnlock::isAvailable() const
{
    return PasskeyUnlock::isAvailable();
}

QString PasskeyQuickUnlock::errorString() const
{
    return m_error;
}

bool PasskeyQuickUnlock::needsSaveAfterStore() const
{
    return true;
}

bool PasskeyQuickUnlock::hasKey(const QSharedPointer<Database>& db) const
{
    if (!db) {
        return false;
    }
    return PasskeyUnlock::isConfigured(db);
}

bool PasskeyQuickUnlock::storeKey(const QSharedPointer<Database>& db, void* parentWindow, QString* error)
{
    m_error.clear();
    if (!db) {
        m_error = QObject::tr("No database loaded.");
        if (error) {
            *error = m_error;
        }
        return false;
    }

    if (!PasskeyUnlock::enable(db, parentWindow, error)) {
        if (error) {
            m_error = *error;
        }
        return false;
    }

    return true;
}

bool PasskeyQuickUnlock::retrieveKey(const QSharedPointer<Database>& db,
                                     QByteArray& serializedKey,
                                     void* parentWindow,
                                     QString* error)
{
    m_error.clear();
    serializedKey.clear();

    if (!db) {
        m_error = QObject::tr("No database loaded.");
        if (error) {
            *error = m_error;
        }
        return false;
    }

    if (!PasskeyUnlock::retrieveSerializedKey(db, parentWindow, serializedKey, error)) {
        if (error) {
            m_error = *error;
        }
        return false;
    }

    return true;
}

void PasskeyQuickUnlock::reset(const QSharedPointer<Database>& db)
{
    if (!db) {
        return;
    }
    PasskeyUnlock::removeRecord(db);
}
