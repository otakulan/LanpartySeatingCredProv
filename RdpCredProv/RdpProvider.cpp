
#include <credentialprovider.h>
#include "RdpProvider.h"
#include "RdpCredential.h"
#include "helpers.h"
#include "guid.h"

#include <shlobj.h>
#include <strsafe.h>

CLogFile log;

RdpProvider::RdpProvider():
	_cRef(1),
	_pkiulSetSerialization(NULL),
	_dwNumCreds(0),
	_bLogEnabled(false),
	_bRemoteOnly(true),
	_bAutoSubmitSetSerializationCred(false),
	_bAutoLogonWithDefault(false),
	_bUseDefaultCredentials(false),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
	_cpus(CPUS_INVALID),
	_pCredentialProviderEvents(NULL),
	_upAdviseContext(0),
	_hPipe(INVALID_HANDLE_VALUE),
	_bHasStoredCredentials(false),
	_hMessageThread(NULL),
	_hStopEvent(NULL),
	_bThreadRunning(false)
{
	DllAddRef();

	ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));
	ZeroMemory(_wszStoredUsername, sizeof(_wszStoredUsername));
	ZeroMemory(_wszStoredPassword, sizeof(_wszStoredPassword));
	ZeroMemory(_wszStoredDomain, sizeof(_wszStoredDomain));

	HKEY hKey;
	DWORD cbSize;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RDPCREDPROV_REGPATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		DWORD dwLogEnabled = 0;
		cbSize = sizeof(dwLogEnabled);
		RegQueryValueExW(hKey, L"LogEnabled", nullptr, nullptr, (LPBYTE)&dwLogEnabled, &cbSize);
		_bLogEnabled = dwLogEnabled ? true : false;

		DWORD dwRemoteOnly = 1;
		cbSize = sizeof(dwRemoteOnly);
		RegQueryValueExW(hKey, L"RemoteOnly", nullptr, nullptr, (LPBYTE)&dwRemoteOnly, &cbSize);
		_bRemoteOnly = dwRemoteOnly ? true : false;

		RegCloseKey(hKey);
	}

	log.m_enabled = _bLogEnabled;

	if (_bLogEnabled) {
		WCHAR logPathW[MAX_PATH] = L"";
		WCHAR baseDir[MAX_PATH] = L"";
		DWORD sessionId = -1;

		if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, baseDir))) {
			wcscpy_s(baseDir, MAX_PATH, L"C:\\ProgramData");
		}

		wcscat_s(baseDir, L"\\RdpCredProv");
		CreateDirectoryW(baseDir, NULL);

		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			sessionId = 0;
		}

		swprintf_s(logPathW, MAX_PATH, L"%s\\winlogon-%u.log", baseDir, sessionId);

		char* logPathA = NULL;
		ConvertFromUnicode(CP_UTF8, 0, logPathW, -1, &logPathA, 0, NULL, NULL);

		if (logPathA) {
			log.OpenFile(logPathA);
			free(logPathA);
		}
	}
}

RdpProvider::~RdpProvider()
{
	_StopBackgroundMessageThread();
	_DisconnectFromDesktopClient();
	
	if (_pCredentialProviderEvents)
	{
		_pCredentialProviderEvents->Release();
		_pCredentialProviderEvents = NULL;
	}

	for (size_t i = 0; i < _dwNumCreds; i++)
	{
		if (_rgpCredentials[i] != NULL)
		{
			_rgpCredentials[i]->Release();
		}
	}

	log.CloseFile();

	DllRelease();
}

void RdpProvider::_CleanupSetSerialization()
{
	if (_pkiulSetSerialization)
	{
		KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
		SecureZeroMemory(_pkiulSetSerialization,
			sizeof(*_pkiulSetSerialization) +
			pkil->LogonDomainName.MaximumLength +
			pkil->UserName.MaximumLength +
			pkil->Password.MaximumLength);
		HeapFree(GetProcessHeap(),0, _pkiulSetSerialization);
	}
}

HRESULT RdpProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(dwFlags);
	HRESULT hr;

	log.Write("DEBUG: SetUsageScenario called - Scenario: %d (%s), Flags: 0x%04X", 
		(int)cpus,
		cpus == CPUS_LOGON ? "LOGON" :
		cpus == CPUS_UNLOCK_WORKSTATION ? "UNLOCK" :
		cpus == CPUS_CREDUI ? "CREDUI" :
		cpus == CPUS_CHANGE_PASSWORD ? "CHANGE_PASSWORD" : "UNKNOWN",
		(int)dwFlags);

	if (_bRemoteOnly) {
		log.Write("DEBUG: RemoteOnly mode enabled");
		if (cpus == CPUS_CREDUI) {
			log.Write("DEBUG: Rejecting CREDUI scenario in RemoteOnly mode");
			return E_NOTIMPL;
		}
	}

	switch (cpus)
	{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
			log.Write("DEBUG: Accepted scenario - proceeding with credential enumeration");
			// Always re-enumerate credentials, don't use static flag
			// This is necessary for dynamic credential providers that get credentials at runtime
			_cpus = cpus;
			log.Write("DEBUG: Calling _EnumerateCredentials");
			hr = this->_EnumerateCredentials();
			log.Write("DEBUG: _EnumerateCredentials returned: 0x%08X", hr);
			break;

		case CPUS_CHANGE_PASSWORD:
			log.Write("DEBUG: CHANGE_PASSWORD scenario not implemented");
			hr = E_NOTIMPL;
			break;

		default:
			log.Write("DEBUG: Unknown scenario - returning E_INVALIDARG");
			hr = E_INVALIDARG;
			break;
	}

	log.Write("DEBUG: SetUsageScenario returning: 0x%08X", hr);
	return hr;
}

STDMETHODIMP RdpProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
	HRESULT hr = E_INVALIDARG;

	log.Write("RdpProvider::SetSerialization");

	if ((CLSID_RdpProvider == pcpcs->clsidCredentialProvider))
	{
		ULONG ulAuthPackage;
		hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

		if (SUCCEEDED(hr))
		{
			if ((ulAuthPackage == pcpcs->ulAuthenticationPackage) && (0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*) pcpcs->rgbSerialization;

				if (KerbInteractiveLogon == pkil->Logon.MessageType)
				{
					BYTE* rgbSerialization;
					rgbSerialization = (BYTE*) HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
					hr = rgbSerialization ? S_OK : E_OUTOFMEMORY;

					if (SUCCEEDED(hr))
					{
						CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
						KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*) rgbSerialization);

						if (_pkiulSetSerialization)
						{
							HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);

							if ((_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT) && (_dwSetSerializationCred == _dwNumCreds - 1))
							{
								_rgpCredentials[_dwSetSerializationCred]->Release();
								_rgpCredentials[_dwSetSerializationCred] = NULL;
								_dwNumCreds--;
								_dwSetSerializationCred = CREDENTIAL_PROVIDER_NO_DEFAULT;
							}
						}

						_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*) rgbSerialization;

						hr = S_OK;
					}
				}
			}
		}
		else
		{
			hr = E_INVALIDARG;
		}
	}

	return hr;
}

HRESULT RdpProvider::Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
	log.Write("DEBUG: Advise called - setting up event callbacks");
	log.Write("DEBUG: ICredentialProviderEvents pointer: %p, AdviseContext: %llu", pcpe, upAdviseContext);

	if (_pCredentialProviderEvents)
	{
		log.Write("DEBUG: Releasing existing credential provider events");
		_pCredentialProviderEvents->Release();
	}

	_pCredentialProviderEvents = pcpe;
	_pCredentialProviderEvents->AddRef();
	_upAdviseContext = upAdviseContext;

	log.Write("DEBUG: Event callbacks set up successfully");

	// Try to connect to desktop client (non-blocking)
	log.Write("DEBUG: Attempting initial connection to desktop client");
	HRESULT hrConnect = _ConnectToDesktopClient();
	log.Write("DEBUG: Initial connection attempt result: 0x%08X", hrConnect);
	
	// Start a background thread to continuously check for messages
	// This ensures we receive trigger messages even when GetCredentialCount isn't called frequently
	log.Write("DEBUG: Starting background message checking thread");
	_StartBackgroundMessageThread();
	
	log.Write("DEBUG: Advise completed - continuous message checking active");

	return S_OK;
}

HRESULT RdpProvider::UnAdvise()
{
	log.Write("DEBUG: UnAdvise called - stopping background thread");

	_StopBackgroundMessageThread();
	_DisconnectFromDesktopClient();

	if (_pCredentialProviderEvents)
	{
		_pCredentialProviderEvents->Release();
		_pCredentialProviderEvents = NULL;
	}

	log.Write("DEBUG: UnAdvise completed");
	return S_OK;
}

HRESULT RdpProvider::GetFieldDescriptorCount(__out DWORD* pdwCount)
{
	*pdwCount = SFI_NUM_FIELDS;
	return S_OK;
}

HRESULT RdpProvider::GetFieldDescriptorAt(DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{    
	HRESULT hr;

	if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
	{
		hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
	}
	else
	{ 
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpProvider::GetCredentialCount(__out DWORD* pdwCount, __out DWORD* pdwDefault, __out BOOL* pbAutoLogonWithDefault)
{
	HRESULT hr = S_OK;

	// Check for incoming messages from desktop client
	_CheckForIncomingMessages();

	// ALWAYS return 1 credential to keep Winlogon polling
	*pdwCount = 1;
	*pdwDefault = 0;
	*pbAutoLogonWithDefault = _bHasStoredCredentials ? TRUE : FALSE;

	return hr;
}

HRESULT RdpProvider::GetCredentialAt(DWORD dwIndex, __out ICredentialProviderCredential** ppcpc)
{
	HRESULT hr;

	if ((dwIndex < _dwNumCreds) && ppcpc)
	{
		hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpProvider::_EnumerateCredentials()
{
    HRESULT hr = S_OK;
    DWORD dwCredentialIndex = 0;
    
    log.Write("DEBUG: _EnumerateCredentials called - HasStoredCredentials: %s", _bHasStoredCredentials ? "true" : "false");

	// Clean up any existing credentials first
	for (size_t i = 0; i < _dwNumCreds; i++)
	{
		if (_rgpCredentials[i] != NULL)
		{
			_rgpCredentials[i]->Release();
			_rgpCredentials[i] = NULL;
		}
	}
	_dwNumCreds = 0;

	// ALWAYS create at least one credential tile to keep Winlogon interested
	// This is the correct Microsoft pattern - never return 0 credentials or Winlogon stops calling
	log.Write("DEBUG: Creating credential tile (required to maintain Winlogon polling)");
	
	if (_bRemoteOnly && !GetSystemMetrics(SM_REMOTESESSION)) {
		log.Write("DEBUG: RemoteOnly mode but not in remote session - still creating placeholder");
	}
	
	RdpCredential* ppc = new RdpCredential();
	if (ppc)
	{
		LPCWSTR pwzUser = L"";
		LPCWSTR pwzPassword = L"";
		LPCWSTR pwzDomain = L"";

		if (_bHasStoredCredentials)
		{
			// Use credentials from desktop client (received via trigger message)
			pwzUser = _wszStoredUsername;
			pwzPassword = _wszStoredPassword;
			pwzDomain = _wszStoredDomain;
			log.Write("DEBUG: Using stored credentials from desktop client - User: %ws", pwzUser);
		}
		else
		{
			// Create empty/placeholder credential to keep Winlogon polling
			// This ensures GetCredentialCount continues to be called
			log.Write("DEBUG: Creating placeholder credential to maintain Winlogon polling");
		}

		hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, 
			pwzUser, pwzPassword, pwzDomain);

		if (SUCCEEDED(hr))
		{
			_rgpCredentials[dwCredentialIndex] = ppc;
			_dwNumCreds++;
			log.Write("DEBUG: Successfully created credential tile - _dwNumCreds: %d", _dwNumCreds);
		}
		else
		{
			ppc->Release();
			log.Write("ERROR: Failed to initialize credential - HRESULT: 0x%08X", hr);
		}
	}
	else
	{
		hr = E_OUTOFMEMORY;
		log.Write("ERROR: Failed to allocate credential object");
	}

    log.Write("DEBUG: _EnumerateCredentials completed - _dwNumCreds: %d, hr: 0x%08X", _dwNumCreds, hr);
    return hr;
}

HRESULT RdpProvider_CreateInstance(REFIID riid, __deref_out void** ppv)
{
	HRESULT hr;

	RdpProvider* pProvider = new RdpProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT RdpProvider::_EnumerateSetSerialization()
{
	KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;

	log.Write("RdpProvider::_EnumerateSetSerialization");

	_bAutoSubmitSetSerializationCred = false;

	if (_bRemoteOnly && !GetSystemMetrics(SM_REMOTESESSION)) {
		return E_FAIL;
	}

	WCHAR wszUsername[MAX_PATH] = { 0 };
	WCHAR wszPassword[MAX_PATH] = { 0 };

	HRESULT hr = StringCbCopyNW(wszUsername, sizeof(wszUsername), pkil->UserName.Buffer, pkil->UserName.Length);

	if (SUCCEEDED(hr))
	{
		hr = StringCbCopyNW(wszPassword, sizeof(wszPassword), pkil->Password.Buffer, pkil->Password.Length);

		if (SUCCEEDED(hr))
		{
			RdpCredential* pCred = new RdpCredential();

			if (pCred)
			{
				hr = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, wszUsername, wszPassword);

				if (SUCCEEDED(hr))
				{
					_rgpCredentials[_dwNumCreds] = pCred;
					_dwSetSerializationCred = _dwNumCreds;
					_dwNumCreds++;
				}
			}
			else
			{
				hr = E_OUTOFMEMORY;
			}

			if (SUCCEEDED(hr) && (0 < wcslen(wszPassword)))
			{
				_bAutoSubmitSetSerializationCred = true;
			}
		}
	}

	return hr;
}

HRESULT RdpProvider::_ConnectToDesktopClient()
{
	log.Write("DEBUG: _ConnectToDesktopClient called - current pipe handle: %p", _hPipe);

	if (_hPipe != INVALID_HANDLE_VALUE)
	{
		log.Write("DEBUG: Already connected to desktop client pipe");
		return S_OK; // Already connected
	}

	log.Write("DEBUG: Attempting to connect to named pipe: \\\\.\\pipe\\Lanpartyseating.Desktop");

	// Try to connect to the desktop client's named pipe (non-blocking)
	_hPipe = CreateFileW(
		L"\\\\.\\pipe\\Lanpartyseating.Desktop",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (_hPipe == INVALID_HANDLE_VALUE)
	{
		DWORD dwError = GetLastError();
		log.Write("DEBUG: Failed to connect to desktop client pipe. Error: %d (%s)", 
			dwError, 
			dwError == ERROR_FILE_NOT_FOUND ? "FILE_NOT_FOUND - service not running" :
			dwError == ERROR_PIPE_BUSY ? "PIPE_BUSY - service busy" :
			dwError == ERROR_ACCESS_DENIED ? "ACCESS_DENIED - permission issue" : "OTHER");
		return HRESULT_FROM_WIN32(dwError);
	}

	log.Write("DEBUG: Successfully connected to desktop client pipe - handle: %p", _hPipe);

	// Send a registration message so the desktop client knows we're here
	char registerMessage[512];
	_BuildCredentialProviderConnectedMessage(registerMessage, sizeof(registerMessage));
	
	log.Write("DEBUG: Sending registration message: %s", registerMessage);
	
	DWORD bytesWritten;
	BOOL writeResult = WriteFile(_hPipe, registerMessage, (DWORD)strlen(registerMessage), &bytesWritten, NULL);
	
	if (writeResult)
	{
		log.Write("DEBUG: Successfully sent registration message - %d bytes written", bytesWritten);
	}
	else
	{
		DWORD dwError = GetLastError();
		log.Write("ERROR: Failed to send registration message - error: %d", dwError);
	}

	return S_OK;
}

void RdpProvider::_DisconnectFromDesktopClient()
{
	log.Write("DEBUG: _DisconnectFromDesktopClient called - current pipe handle: %p", _hPipe);

	if (_hPipe != INVALID_HANDLE_VALUE)
	{
		log.Write("DEBUG: Closing pipe handle");
		CloseHandle(_hPipe);
		_hPipe = INVALID_HANDLE_VALUE;
		log.Write("DEBUG: Pipe handle closed and set to INVALID_HANDLE_VALUE");
	}
	else
	{
		log.Write("DEBUG: Pipe handle was already INVALID_HANDLE_VALUE - nothing to close");
	}
}

HRESULT RdpProvider::_RequestCredentialsFromClient(PWSTR* ppwzUsername, PWSTR* ppwzPassword, PWSTR* ppwzDomain)
{
	log.Write("DEBUG: _RequestCredentialsFromClient called");
	log.Write("DEBUG: Current _bHasStoredCredentials: %s", _bHasStoredCredentials ? "true" : "false");

	// If we already have stored credentials, return them
	if (_bHasStoredCredentials)
	{
		log.Write("DEBUG: Using existing stored credentials");
		size_t userLen = wcslen(_wszStoredUsername) + 1;
		size_t passLen = wcslen(_wszStoredPassword) + 1;
		size_t domainLen = wcslen(_wszStoredDomain) + 1;

		*ppwzUsername = (PWSTR)CoTaskMemAlloc(userLen * sizeof(WCHAR));
		*ppwzPassword = (PWSTR)CoTaskMemAlloc(passLen * sizeof(WCHAR));
		*ppwzDomain = (PWSTR)CoTaskMemAlloc(domainLen * sizeof(WCHAR));

		if (*ppwzUsername && *ppwzPassword && *ppwzDomain)
		{
			wcscpy_s(*ppwzUsername, userLen, _wszStoredUsername);
			wcscpy_s(*ppwzPassword, passLen, _wszStoredPassword);
			wcscpy_s(*ppwzDomain, domainLen, _wszStoredDomain);
			log.Write("DEBUG: Successfully returned existing stored credentials");
			return S_OK;
		}
		else
		{
			log.Write("ERROR: Failed to allocate memory for credential strings");
			return E_OUTOFMEMORY;
		}
	}

	log.Write("DEBUG: No stored credentials, requesting from desktop client");
	log.Write("DEBUG: Current pipe handle: %p", _hPipe);

	// Otherwise, request credentials from the desktop client
	if (_hPipe == INVALID_HANDLE_VALUE)
	{
		log.Write("DEBUG: Pipe not connected, attempting connection");
		HRESULT hr = _ConnectToDesktopClient();
		if (FAILED(hr))
		{
			log.Write("ERROR: Failed to connect to desktop client for credential request - HRESULT: 0x%08X", hr);
			return hr;
		}
		log.Write("DEBUG: Connection successful, pipe handle now: %p", _hPipe);
	}

	// Send credential request using proper JSON message
	char credentialRequest[512];
	_BuildCredentialRequestMessage(credentialRequest, sizeof(credentialRequest));
	
	log.Write("DEBUG: Sending credential request: %s", credentialRequest);
	
	DWORD bytesWritten;
	if (!WriteFile(_hPipe, credentialRequest, (DWORD)strlen(credentialRequest), &bytesWritten, NULL))
	{
		DWORD dwError = GetLastError();
		log.Write("ERROR: Failed to send credential request to desktop client - error: %d", dwError);
		return E_FAIL;
	}

	log.Write("DEBUG: Successfully sent credential request - %d bytes written", bytesWritten);

	// Read the response with a timeout
	char buffer[1024];
	DWORD bytesRead;
	if (ReadFile(_hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL))
	{
		buffer[bytesRead] = '\0';
		log.Write("DEBUG: Received credential response (%d bytes): %s", bytesRead, buffer);

		// Parse the JSON response to extract credentials
		if (ParseCredentialResponse(buffer))
		{
			log.Write("DEBUG: Successfully parsed credential response");
			log.Write("DEBUG: _bHasStoredCredentials is now: %s", _bHasStoredCredentials ? "true" : "false");
			
			// Return the newly stored credentials
			size_t userLen = wcslen(_wszStoredUsername) + 1;
			size_t passLen = wcslen(_wszStoredPassword) + 1;
			size_t domainLen = wcslen(_wszStoredDomain) + 1;

			*ppwzUsername = (PWSTR)CoTaskMemAlloc(userLen * sizeof(WCHAR));
			*ppwzPassword = (PWSTR)CoTaskMemAlloc(passLen * sizeof(WCHAR));
			*ppwzDomain = (PWSTR)CoTaskMemAlloc(domainLen * sizeof(WCHAR));

			if (*ppwzUsername && *ppwzPassword && *ppwzDomain)
			{
				wcscpy_s(*ppwzUsername, userLen, _wszStoredUsername);
				wcscpy_s(*ppwzPassword, passLen, _wszStoredPassword);
				wcscpy_s(*ppwzDomain, domainLen, _wszStoredDomain);
				log.Write("DEBUG: Successfully returned newly received credentials");
				return S_OK;
			}
			else
			{
				log.Write("ERROR: Failed to allocate memory for credential return strings");
				return E_OUTOFMEMORY;
			}
		}
		else
		{
			log.Write("ERROR: Failed to parse credential response");
		}
	}
	else
	{
		DWORD dwError = GetLastError();
		log.Write("ERROR: Failed to read credential response - error: %d", dwError);
	}

	log.Write("ERROR: Failed to get credentials from desktop client");
	return E_FAIL;
}

void RdpProvider::_CheckForIncomingMessages()
{
	if (_hPipe == INVALID_HANDLE_VALUE)
	{
		// Try to reconnect periodically
		static DWORD lastReconnectAttempt = 0;
		DWORD currentTime = GetTickCount();
		if ((currentTime - lastReconnectAttempt) > 5000) // Try reconnect every 5 seconds
		{
			_ConnectToDesktopClient();
			lastReconnectAttempt = currentTime;
		}
		return;
	}

	// Check if there's data available to read (non-blocking)
	DWORD bytesAvailable = 0;
	BOOL result = PeekNamedPipe(_hPipe, NULL, 0, NULL, &bytesAvailable, NULL);
	
	if (!result)
	{
		// Pipe broken, disconnect and retry later
		_DisconnectFromDesktopClient();
		return;
	}

	if (bytesAvailable == 0)
	{
		return; // No data available
	}
	char buffer[1024];
	DWORD bytesRead;
	result = ReadFile(_hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);

	if (result && bytesRead > 0)
	{
		buffer[bytesRead] = '\0';
		log.Write("Received message from desktop client: %s", buffer);

		// Parse the trigger login message
		if (strstr(buffer, "\"$type\":\"triggerloginrequest\""))
		{
			log.Write("Processing TriggerLoginRequest - requesting credentials");
			
			// Request credentials from desktop client immediately
			PWSTR pwzUsername = nullptr, pwzPassword = nullptr, pwzDomain = nullptr;
			HRESULT hrRequest = _RequestCredentialsFromClient(&pwzUsername, &pwzPassword, &pwzDomain);
			
			if (SUCCEEDED(hrRequest) && pwzUsername && pwzPassword)
			{
				log.Write("Received credentials for user: %ws", pwzUsername);
				
				// Update the existing credential tile with the new credentials
				if (_dwNumCreds > 0 && _rgpCredentials[0])
				{
					RdpCredential* pCred = static_cast<RdpCredential*>(_rgpCredentials[0]);
					pCred->UpdateCredentials(pwzUsername, pwzPassword, pwzDomain);
				}
				
				// Clean up the allocated strings
				CoTaskMemFree(pwzUsername);
				CoTaskMemFree(pwzPassword);
				CoTaskMemFree(pwzDomain);
				
				// Call CredentialsChanged to trigger auto-login
				if (_pCredentialProviderEvents)
				{
					log.Write("Triggering Windows auto-login");
					_pCredentialProviderEvents->CredentialsChanged(_upAdviseContext);
				}
			}
			else
			{
				log.Write("ERROR: Failed to get credentials after trigger message");
			}
		}
	}
	else
	{
		log.Write("ERROR: Failed to read message from pipe");
	}
}

// JSON Message builders for strongly typed communication with C# desktop client
void RdpProvider::_BuildCredentialProviderConnectedMessage(char* buffer, size_t bufferSize)
{
	sprintf_s(buffer, bufferSize, 
		"{"
		"\"$type\":\"credentialproviderconnected\","
		"\"ProcessId\":%d,"
		"\"Timestamp\":%lld"
		"}\n",
		GetCurrentProcessId(),
		GetTickCount64()
	);
}

void RdpProvider::_BuildCredentialRequestMessage(char* buffer, size_t bufferSize)
{
	sprintf_s(buffer, bufferSize, 
		"{"
		"\"$type\":\"credentialrequest\","
		"\"ProcessId\":%d,"
		"\"Timestamp\":%lld"
		"}\n",
		GetCurrentProcessId(),
		GetTickCount64()
	);
}

bool RdpProvider::ParseCredentialResponse(const char* jsonResponse)
{
	log.Write("DEBUG: ParseCredentialResponse called with: %s", jsonResponse);

	// Clear existing credentials
	log.Write("DEBUG: Clearing existing stored credentials");
	SecureZeroMemory(_wszStoredUsername, sizeof(_wszStoredUsername));
	SecureZeroMemory(_wszStoredPassword, sizeof(_wszStoredPassword));
	SecureZeroMemory(_wszStoredDomain, sizeof(_wszStoredDomain));
	_bHasStoredCredentials = false;

	// Check if the response indicates success
	if (strstr(jsonResponse, "\"Success\":false"))
	{
		log.Write("ERROR: Credential response indicates failure");
		return false;
	}

	log.Write("DEBUG: Credential response indicates success, parsing fields");

	// Parse the JSON response (simple parsing)
	const char* username_start = strstr(jsonResponse, "\"Username\":\"");
	const char* password_start = strstr(jsonResponse, "\"Password\":\"");
	const char* domain_start = strstr(jsonResponse, "\"Domain\":\"");
	
	log.Write("DEBUG: Field positions - Username: %p, Password: %p, Domain: %p", 
		username_start, password_start, domain_start);
	
	if (username_start && password_start)
	{
		// Extract username
		username_start += 12; // Skip "Username":"
		const char* username_end = strchr(username_start, '"');
		if (username_end)
		{
			size_t username_len = username_end - username_start;
			log.Write("DEBUG: Extracting username - length: %zu", username_len);
			size_t max_username_chars = sizeof(_wszStoredUsername)/sizeof(WCHAR) - 1;
			if (username_len > max_username_chars) {
				log.Write("WARNING: Username length (%zu) exceeds buffer size (%zu), truncating", username_len, max_username_chars);
				username_len = max_username_chars;
			}
			log.Write("DEBUG: Extracting username - length: %zu", username_len);
			MultiByteToWideChar(CP_UTF8, 0, username_start, (int)username_len, _wszStoredUsername, (int)max_username_chars);
			_wszStoredUsername[username_len] = L'\0'; // Ensure null-termination
			log.Write("DEBUG: Extracted username: %ws", _wszStoredUsername);
		}
		else
		{
			log.Write("ERROR: Could not find end of username field");
		}
		
		// Extract password
		password_start += 12; // Skip "Password":"
		const char* password_end = strchr(password_start, '"');
		if (password_end)
		{
			size_t password_len = password_end - password_start;
			log.Write("DEBUG: Extracting password - length: %zu", password_len);
			MultiByteToWideChar(CP_UTF8, 0, password_start, (int)password_len, _wszStoredPassword, (int)(sizeof(_wszStoredPassword)/sizeof(WCHAR) - 1));
			int pw_chars = MultiByteToWideChar(CP_UTF8, 0, password_start, (int)password_len, _wszStoredPassword, (int)(sizeof(_wszStoredPassword)/sizeof(WCHAR) - 1));
			if (pw_chars == 0) {
				log.Write("ERROR: MultiByteToWideChar failed for password extraction (GetLastError: %lu)", GetLastError());
				_wszStoredPassword[0] = L'\0';
			} else {
				_wszStoredPassword[pw_chars] = L'\0';
				log.Write("DEBUG: Password extracted (length: %zu characters)", wcslen(_wszStoredPassword));
			}
		}
		else
		{
			log.Write("ERROR: Could not find end of password field");
		}
		
		// Extract domain (optional)
		if (domain_start)
		{
			domain_start += 9; // Skip "Domain":"
			const char* domain_end = strchr(domain_start, '"');
			if (domain_end && domain_start != domain_end)
			{
				size_t domain_len = domain_end - domain_start;
				log.Write("DEBUG: Extracting domain - length: %zu", domain_len);
				size_t max_domain_len = sizeof(_wszStoredDomain)/sizeof(WCHAR) - 1;
				if (domain_len > max_domain_len) {
					log.Write("WARNING: Domain field too long (%zu), truncating to %zu characters", domain_len, max_domain_len);
					domain_len = max_domain_len;
				}
				log.Write("DEBUG: Extracting domain - length: %zu", domain_len);
				MultiByteToWideChar(CP_UTF8, 0, domain_start, (int)domain_len, _wszStoredDomain, (int)max_domain_len);
				_wszStoredDomain[domain_len] = L'\0'; // Ensure null-termination
				int domain_chars = MultiByteToWideChar(CP_UTF8, 0, domain_start, (int)domain_len, _wszStoredDomain, (int)(sizeof(_wszStoredDomain)/sizeof(WCHAR) - 1));
				if (domain_chars == 0) {
					_wszStoredDomain[0] = L'\0';
					log.Write("ERROR: Failed to convert domain to wide char (MultiByteToWideChar failed)");
				} else {
					_wszStoredDomain[domain_chars] = L'\0';
					log.Write("DEBUG: Extracted domain: %ws", _wszStoredDomain);
				}
			}
			else
			{
				log.Write("DEBUG: Domain field is empty or malformed");
			}
		}
		else
		{
			log.Write("DEBUG: No domain field found in response");
		}
		
		_bHasStoredCredentials = true;
		log.Write("DEBUG: Successfully parsed all credentials - _bHasStoredCredentials set to true");
		log.Write("DEBUG: Final stored credentials - User: %ws, Domain: %ws, Password: [%zu chars]", 
			_wszStoredUsername, _wszStoredDomain, wcslen(_wszStoredPassword));
		return true;
	}

	log.Write("ERROR: Failed to find username and password fields in credential response");
	return false;
}

void RdpProvider::_StartBackgroundMessageThread()
{
	log.Write("DEBUG: _StartBackgroundMessageThread called");
	
	if (_bThreadRunning)
	{
		log.Write("DEBUG: Background thread already running");
		return;
	}

	// Create stop event
	_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!_hStopEvent)
	{
		log.Write("ERROR: Failed to create stop event for background thread");
		return;
	}

	// Create background thread
	_hMessageThread = CreateThread(NULL, 0, _BackgroundMessageThreadProc, this, 0, NULL);
	if (!_hMessageThread)
	{
		log.Write("ERROR: Failed to create background message thread");
		CloseHandle(_hStopEvent);
		_hStopEvent = NULL;
		return;
	}

	_bThreadRunning = true;
	log.Write("DEBUG: Background message thread started successfully");
}

void RdpProvider::_StopBackgroundMessageThread()
{
	log.Write("DEBUG: _StopBackgroundMessageThread called");
	
	if (!_bThreadRunning)
	{
		log.Write("DEBUG: Background thread not running");
		return;
	}

	_bThreadRunning = false;

	// Signal stop event
	if (_hStopEvent)
	{
		log.Write("DEBUG: Signaling stop event");
		SetEvent(_hStopEvent);
	}

	// Wait for thread to terminate
	if (_hMessageThread)
	{
		log.Write("DEBUG: Waiting for background thread to terminate");
		WaitForSingleObject(_hMessageThread, 5000); // 5 second timeout
		CloseHandle(_hMessageThread);
		_hMessageThread = NULL;
		log.Write("DEBUG: Background thread terminated");
	}

	// Clean up stop event
	if (_hStopEvent)
	{
		CloseHandle(_hStopEvent);
		_hStopEvent = NULL;
	}

	log.Write("DEBUG: Background message thread stopped");
}

DWORD WINAPI RdpProvider::_BackgroundMessageThreadProc(LPVOID lpParam)
{
	RdpProvider* pProvider = static_cast<RdpProvider*>(lpParam);
	
	log.Write("DEBUG: Background message thread started");

	// Try to establish initial connection to desktop client
	if (pProvider->_hPipe == INVALID_HANDLE_VALUE)
	{
		log.Write("DEBUG: Background thread attempting initial connection");
		pProvider->_ConnectToDesktopClient();
	}

	while (pProvider->_bThreadRunning)
	{
		// Check for messages (this will handle reconnection if needed)
		pProvider->_CheckForIncomingMessages();

		// Wait for stop event or timeout (1 second polling interval)
		DWORD waitResult = WaitForSingleObject(pProvider->_hStopEvent, 1000);
		if (waitResult == WAIT_OBJECT_0)
		{
			log.Write("DEBUG: Background thread received stop signal");
			break;
		}
		// WAIT_TIMEOUT is expected and means continue polling
	}

	log.Write("DEBUG: Background message thread exiting");
	return 0;
}
