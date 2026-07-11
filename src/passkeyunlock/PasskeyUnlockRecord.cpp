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

#include "PasskeyUnlockRecord.h"

#include <QDataStream>
#include <QIODevice>

#include <cstring>

bool PasskeyUnlockRecord::isValid() const
{
    return credentialId.size() > 0 && prfSalt.size() == PRF_SALT_SIZE && hkdfSalt.size() == HKDF_SALT_SIZE
           && !hkdfInfo.isEmpty() && aeadAlgId == AEAD_AES_256_GCM && aeadNonce.size() == AEAD_NONCE_SIZE
           && wrappedKey.size() > 0 && !publicUuid.isNull();
}

QByteArray PasskeyUnlockRecord::associatedData() const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.writeRawData(MAGIC, sizeof(MAGIC));
    stream << FORMAT_VERSION;
    stream << publicUuid.toRfc4122();
    stream << credentialId;
    return data;
}

QByteArray PasskeyUnlockRecord::serialize() const
{
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream.writeRawData(MAGIC, sizeof(MAGIC));
    stream << FORMAT_VERSION;
    stream << credentialId;
    stream << prfSalt;
    stream << hkdfSalt;
    stream << hkdfInfo;
    stream << aeadAlgId;
    stream << aeadNonce;
    stream << wrappedKey;
    stream << publicUuid.toRfc4122();
    return data;
}

bool PasskeyUnlockRecord::deserialize(const QByteArray& data)
{
    if (data.size() < 8) {
        return false;
    }

    QDataStream stream(data);
    char magic[4];
    stream.readRawData(magic, sizeof(magic));
    if (memcmp(magic, MAGIC, sizeof(MAGIC)) != 0) {
        return false;
    }

    quint16 version = 0;
    stream >> version;
    if (version != FORMAT_VERSION) {
        return false;
    }

    QByteArray uuidData;
    stream >> credentialId;
    stream >> prfSalt;
    stream >> hkdfSalt;
    stream >> hkdfInfo;
    stream >> aeadAlgId;
    stream >> aeadNonce;
    stream >> wrappedKey;
    stream >> uuidData;

    if (stream.status() != QDataStream::Ok) {
        return false;
    }

    if (uuidData.size() != 16) {
        return false;
    }

    publicUuid = QUuid::fromRfc4122(uuidData);
    return isValid();
}
