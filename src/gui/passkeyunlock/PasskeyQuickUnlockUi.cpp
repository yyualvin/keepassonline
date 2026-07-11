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

#include "PasskeyQuickUnlockUi.h"

#include "core/Database.h"
#include "gui/MessageBox.h"
#include "passkeyunlock/PasskeyUnlock.h"

namespace PasskeyQuickUnlockUi
{
    Result enable(QWidget* parent, void* parentWindow, const QSharedPointer<Database>& db)
    {
        Result result;

        if (!db || !db->key() || db->key()->keys().isEmpty()) {
            result.outcome = Outcome::Failed;
            result.message = QObject::tr("The database must be unlocked to set up passkey quick unlock.");
            result.messageType = KMessageWidget::Warning;
            return result;
        }

        if (!PasskeyUnlock::isAvailable()) {
            result.outcome = Outcome::Failed;
            result.message = QObject::tr("WebAuthn with PRF support is not available on this system.");
            result.messageType = KMessageWidget::Error;
            return result;
        }

        if (PasskeyUnlock::isConfigured(db)) {
            const auto dialogResult = MessageBox::question(parent,
                                                           QObject::tr("Passkey Quick Unlock"),
                                                           QObject::tr("Passkey quick unlock is already configured for this database. "
                                                                       "Do you want to replace the existing configuration?"),
                                                           MessageBox::Yes | MessageBox::No,
                                                           MessageBox::No);
            if (dialogResult != MessageBox::Yes) {
                return result;
            }
        }

        QString error;
        if (!PasskeyUnlock::enable(db, parentWindow, &error)) {
            result.outcome = Outcome::Failed;
            result.message = error;
            result.messageType = KMessageWidget::Error;
            return result;
        }

        result.outcome = Outcome::Success;
        return result;
    }

    Result disable(QWidget* parent, const QSharedPointer<Database>& db)
    {
        Result result;

        if (!db || !db->key() || db->key()->keys().isEmpty()) {
            result.outcome = Outcome::Failed;
            result.message = QObject::tr("The database must be unlocked to remove passkey quick unlock.");
            result.messageType = KMessageWidget::Warning;
            return result;
        }

        if (!PasskeyUnlock::isConfigured(db)) {
            result.outcome = Outcome::Failed;
            result.message = QObject::tr("Passkey quick unlock is not configured for this database.");
            result.messageType = KMessageWidget::Information;
            return result;
        }

        const auto dialogResult = MessageBox::question(parent,
                                                       QObject::tr("Passkey Quick Unlock"),
                                                       QObject::tr("Remove passkey quick unlock from this database?"),
                                                       MessageBox::Yes | MessageBox::No,
                                                       MessageBox::No);
        if (dialogResult != MessageBox::Yes) {
            return result;
        }

        QString error;
        if (!PasskeyUnlock::disable(db, &error)) {
            result.outcome = Outcome::Failed;
            result.message = error;
            result.messageType = KMessageWidget::Error;
            return result;
        }

        result.outcome = Outcome::Success;
        return result;
    }
} // namespace PasskeyQuickUnlockUi
