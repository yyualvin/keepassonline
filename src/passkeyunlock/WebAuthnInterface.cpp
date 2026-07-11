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

#include "WebAuthnInterface.h"

#include <QObject>

namespace
{
    class WebAuthnStub : public WebAuthnInterface
    {
    public:
        bool isAvailable() const override
        {
            return false;
        }

        QString errorString() const override
        {
            return m_error;
        }

        bool registerCredential(void*,
                                const QString&,
                                const QByteArray&,
                                const QByteArray&,
                                QByteArray&,
                                QByteArray&,
                                QString* error = nullptr) override
        {
            m_error = QObject::tr("WebAuthn is not available on this platform.");
            if (error) {
                *error = m_error;
            }
            return false;
        }

        bool evaluatePrf(void*,
                           const QString&,
                           const QByteArray&,
                           const QByteArray&,
                           QByteArray&,
                           QString* error = nullptr) override
        {
            m_error = QObject::tr("WebAuthn is not available on this platform.");
            if (error) {
                *error = m_error;
            }
            return false;
        }

    private:
        QString m_error;
    };
} // namespace

WebAuthnInterface* getWebAuthn()
{
    static WebAuthnStub stub;
    return &stub;
}
