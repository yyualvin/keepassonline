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

#include "PasskeyUnlockEditWidget.h"
#include "ui_KeyComponentWidget.h"

#include "core/Database.h"
#include "gui/passkeyunlock/PasskeyQuickUnlockUi.h"
#include "passkeyunlock/PasskeyUnlock.h"

PasskeyUnlockEditWidget::PasskeyUnlockEditWidget(QWidget* parent)
    : KeyComponentWidget(parent)
{
    initComponent();

    m_ui->changeButton->setVisible(false);

    disconnect(m_ui->addButton, nullptr, this, nullptr);
    disconnect(m_ui->removeButton, nullptr, this, nullptr);

    connect(m_ui->addButton, SIGNAL(clicked()), SLOT(enablePasskeyQuickUnlock()));
    connect(m_ui->removeButton, SIGNAL(clicked()), SLOT(disablePasskeyQuickUnlock()));
}

PasskeyUnlockEditWidget::~PasskeyUnlockEditWidget() = default;

void PasskeyUnlockEditWidget::loadSettings(const QSharedPointer<Database>& db)
{
    m_db = db;
    setVisible(PasskeyUnlock::isAvailable());
    refreshState();
}

void PasskeyUnlockEditWidget::refreshState()
{
    if (!PasskeyUnlock::isAvailable()) {
        setVisible(false);
        return;
    }

    setComponentAdded(m_db && PasskeyUnlock::isConfigured(m_db));
}

void PasskeyUnlockEditWidget::setSaveDatabaseCallback(const std::function<bool()>& callback)
{
    m_saveDatabaseCallback = callback;
}

void PasskeyUnlockEditWidget::setShowMessageCallback(
    const std::function<void(const QString&, KMessageWidget::MessageType)>& callback)
{
    m_showMessageCallback = callback;
}

bool PasskeyUnlockEditWidget::addToCompositeKey(QSharedPointer<CompositeKey> key)
{
    Q_UNUSED(key);
    return false;
}

bool PasskeyUnlockEditWidget::validate(QString& errorMessage) const
{
    Q_UNUSED(errorMessage);
    return true;
}

QWidget* PasskeyUnlockEditWidget::componentEditWidget()
{
    return new QWidget();
}

void PasskeyUnlockEditWidget::initComponentEditWidget(QWidget* widget)
{
    Q_UNUSED(widget);
}

void PasskeyUnlockEditWidget::initComponent()
{
    m_ui->groupBox->setTitle(tr("Passkey Quick Unlock"));
    m_ui->addButton->setText(tr("Add Passkey Quick Unlock"));
    m_ui->changeButton->setText(tr("Change Passkey Quick Unlock"));
    m_ui->removeButton->setText(tr("Remove Passkey Quick Unlock"));
    m_ui->changeOrRemoveLabel->setText(tr("Passkey quick unlock configured, click to remove"));

    m_ui->componentDescription->setText(
        tr("<p>Passkey quick unlock lets you unlock this database with a platform passkey.</p>"
           "<p>The database key is wrapped and stored in the database; your passkey is stored by the platform "
           "authenticator.</p>"));
}

void PasskeyUnlockEditWidget::enablePasskeyQuickUnlock()
{
    if (!m_db) {
        return;
    }

    const auto result =
        PasskeyQuickUnlockUi::enable(this, reinterpret_cast<void*>(window()->winId()), m_db);
    if (result.outcome == PasskeyQuickUnlockUi::Outcome::Cancelled) {
        return;
    }
    if (result.outcome == PasskeyQuickUnlockUi::Outcome::Failed) {
        showMessage(result.message, result.messageType);
        return;
    }

    if (!m_saveDatabaseCallback || !m_saveDatabaseCallback()) {
        showMessage(tr("Passkey quick unlock was configured but saving the database failed."),
                    KMessageWidget::Warning);
        refreshState();
        return;
    }

    refreshState();
    showMessage(tr("Passkey quick unlock enabled."), KMessageWidget::Positive);
}

void PasskeyUnlockEditWidget::disablePasskeyQuickUnlock()
{
    if (!m_db) {
        return;
    }

    const auto result = PasskeyQuickUnlockUi::disable(this, m_db);
    if (result.outcome == PasskeyQuickUnlockUi::Outcome::Cancelled) {
        return;
    }
    if (result.outcome == PasskeyQuickUnlockUi::Outcome::Failed) {
        showMessage(result.message, result.messageType);
        return;
    }

    if (!m_saveDatabaseCallback || !m_saveDatabaseCallback()) {
        showMessage(tr("Passkey quick unlock was removed but saving the database failed."), KMessageWidget::Warning);
        refreshState();
        return;
    }

    refreshState();
    showMessage(tr("Passkey quick unlock removed."), KMessageWidget::Positive);
}

void PasskeyUnlockEditWidget::showMessage(const QString& text, KMessageWidget::MessageType type)
{
    if (m_showMessageCallback) {
        m_showMessageCallback(text, type);
    }
}
