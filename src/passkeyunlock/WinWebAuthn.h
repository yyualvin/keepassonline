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

#ifndef KEEPASSX_WIN_WEBAUTHN_H
#define KEEPASSX_WIN_WEBAUTHN_H

#include "WebAuthnInterface.h"

class WinWebAuthn : public WebAuthnInterface
{
public:
    WinWebAuthn();
    ~WinWebAuthn() override;

    bool isAvailable() const override;
    QString errorString() const override;

    bool registerCredential(void* parentWindow,
                            const QString& rpId,
                            const QByteArray& userId,
                            const QByteArray& prfSalt,
                            QByteArray& credentialId,
                            QByteArray& prfOutput,
                            QString* error = nullptr) override;

    bool evaluatePrf(void* parentWindow,
                       const QString& rpId,
                       const QByteArray& credentialId,
                       const QByteArray& prfSalt,
                       QByteArray& prfOutput,
                       QString* error = nullptr) override;

private:
    bool ensureLoaded(QString* error);
    bool makeCredential(void* parentWindow,
                        const QString& rpId,
                        const QString& userName,
                        const QByteArray& userId,
                        const QByteArray& challenge,
                        QByteArray& credentialId,
                        QString* error);
    bool getAssertion(void* parentWindow,
                      const QString& rpId,
                      const QByteArray& challenge,
                      const QByteArray& credentialId,
                      const QByteArray& prfSalt,
                      QByteArray& prfOutput,
                      QString* error);

    mutable QString m_error;
    mutable bool m_checkedAvailability = false;
    mutable bool m_available = false;
};

#endif // KEEPASSX_WIN_WEBAUTHN_H
