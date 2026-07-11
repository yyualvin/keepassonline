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

#ifndef KEEPASSX_HKDF_H
#define KEEPASSX_HKDF_H

#include <QByteArray>

namespace Hkdf
{
    /**
     * Derive key material using HKDF-SHA256 (Botan HKDF-Expand).
     *
     * @param secret input keying material (e.g. PRF output)
     * @param salt HKDF salt
     * @param info domain separation context
     * @param length output length in bytes (default 32)
     * @return derived key or empty QByteArray on failure
     */
    QByteArray sha256(const QByteArray& secret, const QByteArray& salt, const QByteArray& info, size_t length = 32);
} // namespace Hkdf

#endif // KEEPASSX_HKDF_H
