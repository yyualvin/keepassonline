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

#ifndef KEEPASSX_PASSKEY_UNLOCK_RECORD_H
#define KEEPASSX_PASSKEY_UNLOCK_RECORD_H

#include <QByteArray>
#include <QUuid>

class PasskeyUnlockRecord
{
public:
    static constexpr char MAGIC[4] = {'K', 'P', 'Q', 'U'};
    static constexpr quint16 FORMAT_VERSION = 1;
    static constexpr quint16 AEAD_AES_256_GCM = 1;
    static constexpr int PRF_SALT_SIZE = 32;
    static constexpr int HKDF_SALT_SIZE = 32;
    static constexpr int AEAD_NONCE_SIZE = 12;

    QByteArray credentialId;
    QByteArray prfSalt;
    QByteArray hkdfSalt;
    QByteArray hkdfInfo;
    quint16 aeadAlgId = AEAD_AES_256_GCM;
    QByteArray aeadNonce;
    QByteArray wrappedKey;
    QUuid publicUuid;

    bool isValid() const;
    QByteArray associatedData() const;
    QByteArray serialize() const;
    bool deserialize(const QByteArray& data);
};

#endif // KEEPASSX_PASSKEY_UNLOCK_RECORD_H
