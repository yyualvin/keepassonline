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
#include "gui/MessageBox.h"
#include "quickunlock/QuickUnlockInterface.h"

PasskeyUnlockEditWidget::PasskeyUnlockEditWidget(QWidget* parent)
    : KeyComponentWidget(parent)
{
    initComponent();

    m_ui->changeButton->setVisible(false);

    // Add/remove are handled here directly; skip KeyComponentWidget's edit-page flow.
    disconnect(m_ui->addButton, SIGNAL(clicked(bool)), this, SIGNAL(componentAddRequested()));
    disconnect(m_ui->removeButton, SIGNAL(clicked(bool)), this, SIGNAL(componentRemovalRequested()));
    connect(m_ui->addButton, SIGNAL(clicked()), SLOT(enablePasskeyQuickUnlock()));
    connect(m_ui->removeButton, SIGNAL(clicked()), SLOT(disablePasskeyQuickUnlock()));
}

PasskeyUnlockEditWidget::~PasskeyUnlockEditWidget() = default;

void PasskeyUnlockEditWidget::loadSettings(const QSharedPointer<Database>& db)
{
    m_db = db;
    refreshState();
}

void PasskeyUnlockEditWidget::refreshState()
{
    const bool available = getQuickUnlock()->isAvailable();
    setEnabled(available);
    setComponentAdded(available && m_db && getQuickUnlock()->hasKey(m_db));
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
    m_ui->groupBox->setTitle(tr("Quick Unlock"));
    m_ui->addButton->setText(tr("Add Quick Unlock"));
    m_ui->removeButton->setText(tr("Remove Quick Unlock"));
    m_ui->changeOrRemoveLabel->setText(tr("Quick unlock is configured for this database, click to remove"));

    m_ui->componentDescription->setText(
        tr("<p>Quick unlock lets you unlock this database without entering your full credentials.</p>"
           "<p>On Windows, the database key is wrapped and stored in the database file using a passkey. "
           "On other platforms, quick unlock is kept for the current session only.</p>"));
}

void PasskeyUnlockEditWidget::enablePasskeyQuickUnlock()
{
    if (!m_db || !getQuickUnlock()->isAvailable() || getQuickUnlock()->hasKey(m_db)) {
        return;
    }

    QString error;
    const auto parentWindow = reinterpret_cast<void*>(window()->winId());
    if (!getQuickUnlock()->storeKey(m_db, parentWindow, &error)) {
        showMessage(error.isEmpty() ? tr("Failed to enable quick unlock.") : error, KMessageWidget::Error);
        refreshState();
        return;
    }

    if (getQuickUnlock()->needsSaveAfterStore()) {
        if (!m_saveDatabaseCallback || !m_saveDatabaseCallback()) {
            showMessage(tr("Quick unlock was configured but saving the database failed."), KMessageWidget::Warning);
            refreshState();
            return;
        }
    }

    refreshState();
    showMessage(tr("Quick unlock enabled."), KMessageWidget::Positive);
}

void PasskeyUnlockEditWidget::disablePasskeyQuickUnlock()
{
    if (!m_db || !getQuickUnlock()->hasKey(m_db)) {
        return;
    }

    const auto dialogResult = MessageBox::question(this,
                                                   tr("Quick Unlock"),
                                                   tr("Remove quick unlock from this database?"),
                                                   MessageBox::Yes | MessageBox::No,
                                                   MessageBox::No);
    if (dialogResult != MessageBox::Yes) {
        if (getQuickUnlock()->hasKey(m_db)) {
            changeVisiblePage(Page::LeaveOrRemove);
        }
        return;
    }

    getQuickUnlock()->reset(m_db);

    if (getQuickUnlock()->needsSaveAfterStore()) {
        if (!m_saveDatabaseCallback || !m_saveDatabaseCallback()) {
            showMessage(tr("Quick unlock was removed but saving the database failed."), KMessageWidget::Warning);
            refreshState();
            return;
        }
    }

    refreshState();
    showMessage(tr("Quick unlock removed."), KMessageWidget::Positive);
}

void PasskeyUnlockEditWidget::showMessage(const QString& text, KMessageWidget::MessageType type)
{
    if (m_showMessageCallback) {
        m_showMessageCallback(text, type);
    }
}
