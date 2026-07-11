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

#ifndef KEEPASSXC_PASSKEYQUICKUNLOCKUI_H
#define KEEPASSXC_PASSKEYQUICKUNLOCKUI_H

#include "gui/KMessageWidget.h"

#include <QSharedPointer>
#include <QString>

class Database;
class QWidget;

namespace PasskeyQuickUnlockUi
{
    enum class Outcome
    {
        Cancelled,
        Failed,
        Success
    };

    struct Result
    {
        Outcome outcome = Outcome::Cancelled;
        QString message;
        KMessageWidget::MessageType messageType = KMessageWidget::Information;
    };

    Result enable(QWidget* parent, void* parentWindow, const QSharedPointer<Database>& db);
    Result disable(QWidget* parent, const QSharedPointer<Database>& db);
} // namespace PasskeyQuickUnlockUi

#endif // KEEPASSXC_PASSKEYQUICKUNLOCKUI_H
