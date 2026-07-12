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

#include "DatabaseSettingsWidgetQuickUnlock.h"

#include "gui/databasekey/PasskeyUnlockEditWidget.h"
#include "quickunlock/QuickUnlockInterface.h"

#include <QVBoxLayout>

DatabaseSettingsWidgetQuickUnlock::DatabaseSettingsWidgetQuickUnlock(QWidget* parent)
    : DatabaseSettingsWidget(parent)
    , m_passkeyUnlockEditWidget(new PasskeyUnlockEditWidget(this))
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSizeConstraint(QLayout::SetNoConstraint);
    layout->addWidget(m_passkeyUnlockEditWidget);
    layout->addStretch();
    setLayout(layout);
    setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
}

DatabaseSettingsWidgetQuickUnlock::~DatabaseSettingsWidgetQuickUnlock() = default;

void DatabaseSettingsWidgetQuickUnlock::setSaveDatabaseCallback(const std::function<bool()>& callback)
{
    m_passkeyUnlockEditWidget->setSaveDatabaseCallback(callback);
}

void DatabaseSettingsWidgetQuickUnlock::setShowMessageCallback(
    const std::function<void(const QString&, KMessageWidget::MessageType)>& callback)
{
    m_passkeyUnlockEditWidget->setShowMessageCallback(callback);
}

void DatabaseSettingsWidgetQuickUnlock::loadSettings(QSharedPointer<Database> db)
{
    DatabaseSettingsWidget::loadSettings(db);
    m_passkeyUnlockEditWidget->loadSettings(db);
    setEnabled(getQuickUnlock()->isAvailable());
}

void DatabaseSettingsWidgetQuickUnlock::initialize()
{
}

void DatabaseSettingsWidgetQuickUnlock::uninitialize()
{
}

bool DatabaseSettingsWidgetQuickUnlock::saveSettings()
{
    return true;
}

void DatabaseSettingsWidgetQuickUnlock::discard()
{
}
