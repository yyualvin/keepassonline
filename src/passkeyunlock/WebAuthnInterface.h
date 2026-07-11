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

#ifndef KEEPASSX_WEBAUTHN_INTERFACE_H
#define KEEPASSX_WEBAUTHN_INTERFACE_H

#include <QByteArray>
#include <QString>

class WebAuthnInterface
{
public:
    virtual ~WebAuthnInterface() = default;

    virtual bool isAvailable() const = 0;
    virtual QString errorString() const = 0;

    /**
     * Register a WebAuthn credential with hmac-secret / PRF support and evaluate the PRF.
     *
     * @param parentWindow native window handle (HWND on Windows)
     * @param rpId relying party identifier
     * @param userId user handle bytes
     * @param prfSalt salt for PRF evaluation (32 bytes)
     * @param credentialId output credential identifier
     * @param prfOutput output 32-byte PRF result
     * @param error optional error message
     */
    virtual bool registerCredential(void* parentWindow,
                                    const QString& rpId,
                                    const QByteArray& userId,
                                    const QByteArray& prfSalt,
                                    QByteArray& credentialId,
                                    QByteArray& prfOutput,
                                    QString* error = nullptr) = 0;

    /**
     * Evaluate the WebAuthn PRF for an existing credential.
     */
    virtual bool evaluatePrf(void* parentWindow,
                               const QString& rpId,
                               const QByteArray& credentialId,
                               const QByteArray& prfSalt,
                               QByteArray& prfOutput,
                               QString* error = nullptr) = 0;
};

WebAuthnInterface* getWebAuthn();

#endif // KEEPASSX_WEBAUTHN_INTERFACE_H
