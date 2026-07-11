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

#include "Hkdf.h"

#include <botan/kdf.h>

#include <QDebug>

namespace Hkdf
{
    QByteArray sha256(const QByteArray& secret, const QByteArray& salt, const QByteArray& info, size_t length)
    {
        if (secret.isEmpty() || length == 0) {
            return {};
        }

        try {
            auto hkdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
            auto derived = hkdf->derive_key(length,
                                            reinterpret_cast<const uint8_t*>(secret.constData()),
                                            secret.size(),
                                            reinterpret_cast<const uint8_t*>(salt.constData()),
                                            salt.size(),
                                            reinterpret_cast<const uint8_t*>(info.constData()),
                                            info.size());
            return QByteArray(reinterpret_cast<const char*>(derived.data()), static_cast<int>(derived.size()));
        } catch (std::exception& e) {
            qWarning("Hkdf::sha256 failed: %s", e.what());
            return {};
        }
    }
} // namespace Hkdf
