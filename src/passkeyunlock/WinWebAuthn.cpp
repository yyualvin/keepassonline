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

#include "WinWebAuthn.h"

#include "core/AsyncTask.h"
#include "core/SecurityPromptFocusWin.h"
#include "crypto/Random.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QScopeGuard>

#include <windows.h>
#include <webauthn.h>

namespace
{
    using PFN_WebAuthNGetApiVersionNumber = decltype(&WebAuthNGetApiVersionNumber);
    using PFN_WebAuthNAuthenticatorMakeCredential = decltype(&WebAuthNAuthenticatorMakeCredential);
    using PFN_WebAuthNAuthenticatorGetAssertion = decltype(&WebAuthNAuthenticatorGetAssertion);
    using PFN_WebAuthNFreeCredentialAttestation = decltype(&WebAuthNFreeCredentialAttestation);
    using PFN_WebAuthNFreeAssertion = decltype(&WebAuthNFreeAssertion);
    using PFN_WebAuthNGetErrorName = decltype(&WebAuthNGetErrorName);

    struct WebAuthnApi
    {
        HMODULE dll = nullptr;
        PFN_WebAuthNGetApiVersionNumber getApiVersion = nullptr;
        PFN_WebAuthNAuthenticatorMakeCredential makeCredential = nullptr;
        PFN_WebAuthNAuthenticatorGetAssertion getAssertion = nullptr;
        PFN_WebAuthNFreeCredentialAttestation freeAttestation = nullptr;
        PFN_WebAuthNFreeAssertion freeAssertion = nullptr;
        PFN_WebAuthNGetErrorName getErrorName = nullptr;
    };

    WebAuthnApi g_api;

    QString hresultToString(HRESULT hr)
    {
        if (g_api.getErrorName) {
            const auto name = g_api.getErrorName(hr);
            if (name) {
                return QString::fromWCharArray(name);
            }
        }
        return QObject::tr("WebAuthn error 0x%1").arg(QString::number(static_cast<quint32>(hr), 16));
    }

    QByteArray buildClientDataJson(const QString& type, const QByteArray& challenge, const QString& origin)
    {
        QJsonObject obj;
        obj.insert("type", type);
        obj.insert("challenge",
                   QString::fromLatin1(
                       challenge.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
        obj.insert("origin", origin);
        return QJsonDocument(obj).toJson(QJsonDocument::Compact);
    }

    bool loadWebAuthnApi(QString* error)
    {
        if (g_api.dll) {
            return true;
        }

        g_api.dll = LoadLibraryW(L"webauthn.dll");
        if (!g_api.dll) {
            if (error) {
                *error = QObject::tr("webauthn.dll is not available on this system.");
            }
            return false;
        }

        g_api.getApiVersion = reinterpret_cast<PFN_WebAuthNGetApiVersionNumber>(
            GetProcAddress(g_api.dll, "WebAuthNGetApiVersionNumber"));
        g_api.makeCredential = reinterpret_cast<PFN_WebAuthNAuthenticatorMakeCredential>(
            GetProcAddress(g_api.dll, "WebAuthNAuthenticatorMakeCredential"));
        g_api.getAssertion = reinterpret_cast<PFN_WebAuthNAuthenticatorGetAssertion>(
            GetProcAddress(g_api.dll, "WebAuthNAuthenticatorGetAssertion"));
        g_api.freeAttestation = reinterpret_cast<PFN_WebAuthNFreeCredentialAttestation>(
            GetProcAddress(g_api.dll, "WebAuthNFreeCredentialAttestation"));
        g_api.freeAssertion =
            reinterpret_cast<PFN_WebAuthNFreeAssertion>(GetProcAddress(g_api.dll, "WebAuthNFreeAssertion"));
        g_api.getErrorName =
            reinterpret_cast<PFN_WebAuthNGetErrorName>(GetProcAddress(g_api.dll, "WebAuthNGetErrorName"));

        if (!g_api.getApiVersion || !g_api.makeCredential || !g_api.getAssertion || !g_api.freeAttestation
            || !g_api.freeAssertion) {
            if (error) {
                *error = QObject::tr("webauthn.dll does not export required functions.");
            }
            FreeLibrary(g_api.dll);
            g_api = {};
            return false;
        }

        if (g_api.getApiVersion() < WEBAUTHN_API_VERSION_4) {
            if (error) {
                *error = QObject::tr("WebAuthn API version does not support PRF / hmac-secret.");
            }
            FreeLibrary(g_api.dll);
            g_api = {};
            return false;
        }

        return true;
    }

    bool extractCredentialId(const WEBAUTHN_CREDENTIAL_ATTESTATION* attestation, QByteArray& credentialId, QString* error)
    {
        if (!attestation || attestation->cbAuthenticatorData == 0 || !attestation->pbAuthenticatorData) {
            if (error) {
                *error = QObject::tr("WebAuthn credential registration returned no data.");
            }
            return false;
        }

        const auto* authData = attestation->pbAuthenticatorData;
        const DWORD authLen = attestation->cbAuthenticatorData;
        if (authLen < 55) {
            if (error) {
                *error = QObject::tr("WebAuthn authenticator data is too short.");
            }
            return false;
        }

        const auto credIdLen = static_cast<quint16>(authData[53]) << 8 | static_cast<quint16>(authData[54]);
        if (authLen < 55 + credIdLen) {
            if (error) {
                *error = QObject::tr("WebAuthn credential ID is missing from authenticator data.");
            }
            return false;
        }

        credentialId = QByteArray(reinterpret_cast<const char*>(authData + 55), credIdLen);
        return true;
    }

    bool extractPrfOutput(const WEBAUTHN_ASSERTION* assertion, QByteArray& prfOutput, QString* error)
    {
        if (!assertion || !assertion->pHmacSecret || assertion->pHmacSecret->cbFirst != WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH
            || !assertion->pHmacSecret->pbFirst) {
            if (error) {
                *error = QObject::tr("The authenticator did not return a PRF / hmac-secret result.");
            }
            return false;
        }

        prfOutput = QByteArray(reinterpret_cast<const char*>(assertion->pHmacSecret->pbFirst),
                               WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH);
        return true;
    }
} // namespace

WinWebAuthn::WinWebAuthn() = default;

WinWebAuthn::~WinWebAuthn() = default;

bool WinWebAuthn::ensureLoaded(QString* error)
{
    return loadWebAuthnApi(error);
}

bool WinWebAuthn::isAvailable() const
{
    if (!m_checkedAvailability) {
        QString error;
        m_available = const_cast<WinWebAuthn*>(this)->ensureLoaded(&error);
        if (!m_available) {
            m_error = error;
        }
        m_checkedAvailability = true;
    }
    return m_available;
}

QString WinWebAuthn::errorString() const
{
    return m_error;
}

bool WinWebAuthn::makeCredential(void* parentWindow,
                                 const QString& rpId,
                                 const QString& userName,
                                 const QByteArray& userId,
                                 const QByteArray& challenge,
                                 QByteArray& credentialId,
                                 QString* error)
{
    if (!ensureLoaded(error)) {
        return false;
    }

    const auto rpIdW = rpId.toStdWString();
    const auto userNameW = userName.toStdWString();
    const auto rpNameW = QStringLiteral("KeePassXC").toStdWString();

    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo{};
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = rpIdW.c_str();
    rpInfo.pwszName = rpNameW.c_str();

    auto userIdCopy = userId;
    WEBAUTHN_USER_ENTITY_INFORMATION userInfo{};
    userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userInfo.cbId = static_cast<DWORD>(userIdCopy.size());
    userInfo.pbId = reinterpret_cast<BYTE*>(userIdCopy.data());
    userInfo.pwszName = userNameW.c_str();
    userInfo.pwszDisplayName = userNameW.c_str();

    const auto origin = QStringLiteral("https://%1").arg(rpId);
    const auto clientDataJson = buildClientDataJson(QStringLiteral("webauthn.create"), challenge, origin);
    auto clientDataCopy = clientDataJson;
    WEBAUTHN_CLIENT_DATA clientData{};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = static_cast<DWORD>(clientDataCopy.size());
    clientData.pbClientDataJSON = reinterpret_cast<BYTE*>(clientDataCopy.data());
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    WEBAUTHN_COSE_CREDENTIAL_PARAMETER credParam{};
    credParam.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    credParam.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    credParam.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS credParams{};
    credParams.cCredentialParameters = 1;
    credParams.pCredentialParameters = &credParam;

    BOOL hmacSecret = TRUE;
    WEBAUTHN_EXTENSION hmacExt{};
    hmacExt.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
    hmacExt.cbExtension = sizeof(BOOL);
    hmacExt.pvExtension = &hmacSecret;
    WEBAUTHN_EXTENSIONS extensions{};
    extensions.cExtensions = 1;
    extensions.pExtensions = &hmacExt;

    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options{};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.Extensions = extensions;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM;
    options.bRequireResidentKey = TRUE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
    options.bEnablePrf = TRUE;
    options.bPreferResidentKey = TRUE;

    // The security prompt may appear behind the application due to a Windows bug.
    // Run the blocking call off the UI thread so the event loop can bring it to the front.
    SecurityPromptFocusWin::queueFocus();
    WEBAUTHN_CREDENTIAL_ATTESTATION* attestation = nullptr;
    const HRESULT hr = AsyncTask::runAndWaitForFuture([&] {
        return g_api.makeCredential(
            static_cast<HWND>(parentWindow), &rpInfo, &userInfo, &credParams, &clientData, &options, &attestation);
    });
    auto freeGuard = qScopeGuard([&] {
        if (attestation) {
            g_api.freeAttestation(attestation);
        }
    });

    if (FAILED(hr)) {
        m_error = hresultToString(hr);
        if (error) {
            *error = m_error;
        }
        return false;
    }

    return extractCredentialId(attestation, credentialId, error);
}

bool WinWebAuthn::getAssertion(void* parentWindow,
                               const QString& rpId,
                               const QByteArray& challenge,
                               const QByteArray& credentialId,
                               const QByteArray& prfSalt,
                               QByteArray& prfOutput,
                               QString* error)
{
    if (!ensureLoaded(error)) {
        return false;
    }

    const auto rpIdW = rpId.toStdWString();
    const auto origin = QStringLiteral("https://%1").arg(rpId);
    const auto clientDataJson = buildClientDataJson(QStringLiteral("webauthn.get"), challenge, origin);
    auto clientDataCopy = clientDataJson;

    WEBAUTHN_CLIENT_DATA clientData{};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = static_cast<DWORD>(clientDataCopy.size());
    clientData.pbClientDataJSON = reinterpret_cast<BYTE*>(clientDataCopy.data());
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    auto credIdCopy = credentialId;
    WEBAUTHN_CREDENTIAL allowCred{};
    allowCred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    allowCred.cbId = static_cast<DWORD>(credIdCopy.size());
    allowCred.pbId = reinterpret_cast<BYTE*>(credIdCopy.data());
    allowCred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    WEBAUTHN_CREDENTIALS credList{};
    credList.cCredentials = 1;
    credList.pCredentials = &allowCred;

    auto prfSaltCopy = prfSalt;
    WEBAUTHN_HMAC_SECRET_SALT salt{};
    salt.cbFirst = static_cast<DWORD>(prfSaltCopy.size());
    salt.pbFirst = reinterpret_cast<BYTE*>(prfSaltCopy.data());

    WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT credSalt{};
    credSalt.cbCredID = static_cast<DWORD>(credIdCopy.size());
    credSalt.pbCredID = reinterpret_cast<BYTE*>(credIdCopy.data());
    credSalt.pHmacSecretSalt = &salt;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES saltValues{};
    saltValues.cCredWithHmacSecretSaltList = 1;
    saltValues.pCredWithHmacSecretSaltList = &credSalt;

    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options{};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.CredentialList = credList;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
    options.pHmacSecretSaltValues = &saltValues;

    // The security prompt may appear behind the application due to a Windows bug.
    // Run the blocking call off the UI thread so the event loop can bring it to the front.
    SecurityPromptFocusWin::queueFocus();
    WEBAUTHN_ASSERTION* assertion = nullptr;
    const HRESULT hr = AsyncTask::runAndWaitForFuture([&] {
        return g_api.getAssertion(static_cast<HWND>(parentWindow), rpIdW.c_str(), &clientData, &options, &assertion);
    });
    auto freeGuard = qScopeGuard([&] {
        if (assertion) {
            g_api.freeAssertion(assertion);
        }
    });

    if (FAILED(hr)) {
        m_error = hresultToString(hr);
        if (error) {
            *error = m_error;
        }
        return false;
    }

    return extractPrfOutput(assertion, prfOutput, error);
}

bool WinWebAuthn::registerCredential(void* parentWindow,
                                   const QString& rpId,
                                   const QByteArray& userId,
                                   const QByteArray& prfSalt,
                                   QByteArray& credentialId,
                                   QByteArray& prfOutput,
                                   QString* error)
{
    if (prfSalt.size() != WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH) {
        m_error = QObject::tr("Invalid PRF salt size.");
        if (error) {
            *error = m_error;
        }
        return false;
    }

    const auto challenge = randomGen()->randomArray(32);
    const auto userName = QStringLiteral("KeePassXC Passkey Quick Unlock");

    if (!makeCredential(parentWindow, rpId, userName, userId, challenge, credentialId, error)) {
        return false;
    }

    const auto assertionChallenge = randomGen()->randomArray(32);
    return getAssertion(parentWindow, rpId, assertionChallenge, credentialId, prfSalt, prfOutput, error);
}

bool WinWebAuthn::evaluatePrf(void* parentWindow,
                              const QString& rpId,
                              const QByteArray& credentialId,
                              const QByteArray& prfSalt,
                              QByteArray& prfOutput,
                              QString* error)
{
    if (prfSalt.size() != WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH) {
        m_error = QObject::tr("Invalid PRF salt size.");
        if (error) {
            *error = m_error;
        }
        return false;
    }

    const auto challenge = randomGen()->randomArray(32);
    return getAssertion(parentWindow, rpId, challenge, credentialId, prfSalt, prfOutput, error);
}

WebAuthnInterface* getWebAuthn()
{
    static WinWebAuthn instance;
    return &instance;
}
