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

#ifndef KEEPASSX_MOCK_WEBAUTHN_H
#define KEEPASSX_MOCK_WEBAUTHN_H

#include "passkeyunlock/WebAuthnInterface.h"

class MockWebAuthn : public WebAuthnInterface
{
public:
    QByteArray prfSecret = QByteArray(32, '\xAB');

    bool isAvailable() const override
    {
        return m_available;
    }

    QString errorString() const override
    {
        return m_error;
    }

    bool registerCredential(void*,
                            const QString&,
                            const QByteArray&,
                            const QByteArray&,
                            QByteArray& credentialId,
                            QByteArray& prfOutput,
                            QString* error = nullptr) override
    {
        if (!m_available) {
            m_error = QStringLiteral("Unavailable");
            if (error) {
                *error = m_error;
            }
            return false;
        }

        credentialId = QByteArray("mock-credential-id");
        prfOutput = prfSecret;
        return true;
    }

    bool evaluatePrf(void*,
                       const QString&,
                       const QByteArray&,
                       const QByteArray&,
                       QByteArray& prfOutput,
                       QString* error = nullptr) override
    {
        if (!m_available) {
            m_error = QStringLiteral("Unavailable");
            if (error) {
                *error = m_error;
            }
            return false;
        }

        prfOutput = prfSecret;
        return true;
    }

    bool m_available = true;
    QString m_error;
};

#endif // KEEPASSX_MOCK_WEBAUTHN_H
