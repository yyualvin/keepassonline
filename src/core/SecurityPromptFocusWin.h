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

#ifndef KEEPASSX_SECURITY_PROMPT_FOCUS_WIN_H
#define KEEPASSX_SECURITY_PROMPT_FOCUS_WIN_H

namespace SecurityPromptFocusWin
{
    /**
     * Work around a Windows bug where the security prompt ("Credential Dialog Xaml Host")
     * used by Windows Hello and WebAuthn appears behind the calling application.
     * Polls for the dialog on the Qt event loop and brings it to the foreground.
     * The event loop must remain running for this to work (e.g. run the blocking
     * system call through AsyncTask).
     */
    void queueFocus();
} // namespace SecurityPromptFocusWin

#endif // KEEPASSX_SECURITY_PROMPT_FOCUS_WIN_H
