/*
 *  Copyright (C) 2023 KeePassXC Team <team@keepassxc.org>
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

#include "QuickUnlockInterface.h"
#include <QObject>

#if defined(Q_OS_MACOS)
#include "TouchID.h"
#define QUICKUNLOCK_IMPLEMENTATION TouchID
#elif defined(Q_CC_MSVC)
#include "PasskeyQuickUnlock.h"
#define QUICKUNLOCK_IMPLEMENTATION PasskeyQuickUnlock
#elif defined(Q_OS_LINUX)
#include "Polkit.h"
#define QUICKUNLOCK_IMPLEMENTATION Polkit
#else
#define QUICKUNLOCK_IMPLEMENTATION NoQuickUnlock
#endif

QUICKUNLOCK_IMPLEMENTATION* quickUnlockInstance = {nullptr};

QuickUnlockInterface* getQuickUnlock()
{
    if (!quickUnlockInstance) {
        quickUnlockInstance = new QUICKUNLOCK_IMPLEMENTATION();
    }
    return quickUnlockInstance;
}

void QuickUnlockInterface::clearSessionStorage(const QSharedPointer<Database>& db)
{
    Q_UNUSED(db);
}

bool NoQuickUnlock::isAvailable() const
{
    return false;
}

QString NoQuickUnlock::errorString() const
{
    return QObject::tr("No Quick Unlock provider is available");
}

bool NoQuickUnlock::hasKey(const QSharedPointer<Database>& db) const
{
    Q_UNUSED(db);
    return false;
}

bool NoQuickUnlock::storeKey(const QSharedPointer<Database>& db, void* parentWindow, QString* error)
{
    Q_UNUSED(db);
    Q_UNUSED(parentWindow);
    Q_UNUSED(error);
    return false;
}

bool NoQuickUnlock::retrieveKey(const QSharedPointer<Database>& db,
                                QByteArray& serializedKey,
                                void* parentWindow,
                                QString* error)
{
    Q_UNUSED(db);
    Q_UNUSED(serializedKey);
    Q_UNUSED(parentWindow);
    Q_UNUSED(error);
    return false;
}

void NoQuickUnlock::reset(const QSharedPointer<Database>& db)
{
    Q_UNUSED(db);
}
