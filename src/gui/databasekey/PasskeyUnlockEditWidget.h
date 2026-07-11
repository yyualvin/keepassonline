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

#ifndef KEEPASSXC_PASSKEYUNLOCKEDITWIDGET_H
#define KEEPASSXC_PASSKEYUNLOCKEDITWIDGET_H

#include "KeyComponentWidget.h"

#include "gui/KMessageWidget.h"

#include <functional>

class Database;

class PasskeyUnlockEditWidget : public KeyComponentWidget
{
    Q_OBJECT

public:
    explicit PasskeyUnlockEditWidget(QWidget* parent = nullptr);
    Q_DISABLE_COPY(PasskeyUnlockEditWidget);
    ~PasskeyUnlockEditWidget() override;

    void loadSettings(const QSharedPointer<Database>& db);
    void refreshState();

    void setSaveDatabaseCallback(const std::function<bool()>& callback);
    void setShowMessageCallback(const std::function<void(const QString&, KMessageWidget::MessageType)>& callback);

    bool addToCompositeKey(QSharedPointer<CompositeKey> key) override;
    bool validate(QString& errorMessage) const override;

protected:
    QWidget* componentEditWidget() override;
    void initComponentEditWidget(QWidget* widget) override;
    void initComponent() override;

private slots:
    void enablePasskeyQuickUnlock();
    void disablePasskeyQuickUnlock();

private:
    void showMessage(const QString& text, KMessageWidget::MessageType type);

    QSharedPointer<Database> m_db;
    std::function<bool()> m_saveDatabaseCallback;
    std::function<void(const QString&, KMessageWidget::MessageType)> m_showMessageCallback;
};

#endif // KEEPASSXC_PASSKEYUNLOCKEDITWIDGET_H
