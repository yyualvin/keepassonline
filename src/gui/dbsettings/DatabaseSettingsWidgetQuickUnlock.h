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

#ifndef KEEPASSXC_DATABASESETTINGSWIDGETQUICKUNLOCK_H
#define KEEPASSXC_DATABASESETTINGSWIDGETQUICKUNLOCK_H

#include "DatabaseSettingsWidget.h"
#include "gui/KMessageWidget.h"

#include <QPointer>
#include <functional>

class PasskeyUnlockEditWidget;

class DatabaseSettingsWidgetQuickUnlock : public DatabaseSettingsWidget
{
    Q_OBJECT

public:
    explicit DatabaseSettingsWidgetQuickUnlock(QWidget* parent = nullptr);
    Q_DISABLE_COPY(DatabaseSettingsWidgetQuickUnlock);
    ~DatabaseSettingsWidgetQuickUnlock() override;

    void loadSettings(QSharedPointer<Database> db) override;

    void setSaveDatabaseCallback(const std::function<bool()>& callback);
    void setShowMessageCallback(const std::function<void(const QString&, KMessageWidget::MessageType)>& callback);

public slots:
    void initialize() override;
    void uninitialize() override;
    bool saveSettings() override;
    void discard() override;

private:
    const QPointer<PasskeyUnlockEditWidget> m_passkeyUnlockEditWidget;
};

#endif // KEEPASSXC_DATABASESETTINGSWIDGETQUICKUNLOCK_H
