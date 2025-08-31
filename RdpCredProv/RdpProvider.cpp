
#include <credentialprovider.h>
#include "RdpProvider.h"
#include "RdpCredential.h"
#include "helpers.h"
#include "guid.h"

#include <shlobj.h>
#include <strsafe.h>
#include <string>
#include <algorithm>
#include <nlohmann/json.hpp>

// Constants for robust JSON parsing and message handling
static const DWORD MAX_RESPONSE_SIZE = 64 * 1024; // 64KB limit for security

CLogFile g_log;

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
	_hMessageThread(NULL),
	_hStopEvent(NULL),
	_bThreadRunning(false)
{
	DllAddRef();

	ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));

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

	g_log.m_enabled = _bLogEnabled;

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
			g_log.OpenFile(logPathA);
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

	g_log.CloseFile();

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

	g_log.Write("DEBUG: SetUsageScenario called - Scenario: %d (%s), Flags: 0x%04X", 
		(int)cpus,
		cpus == CPUS_LOGON ? "LOGON" :
		cpus == CPUS_UNLOCK_WORKSTATION ? "UNLOCK" :
		cpus == CPUS_CREDUI ? "CREDUI" :
		cpus == CPUS_CHANGE_PASSWORD ? "CHANGE_PASSWORD" : "UNKNOWN",
		(int)dwFlags);

	if (_bRemoteOnly) {
		g_log.Write("DEBUG: RemoteOnly mode enabled");
		if (cpus == CPUS_CREDUI) {
			g_log.Write("DEBUG: Rejecting CREDUI scenario in RemoteOnly mode");
			return E_NOTIMPL;
		}
	}

	switch (cpus)
	{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
			g_log.Write("DEBUG: Accepted scenario - proceeding with credential enumeration");
			// Always re-enumerate credentials, don't use static flag
			// This is necessary for dynamic credential providers that get credentials at runtime
			_cpus = cpus;
			g_log.Write("DEBUG: Calling _EnumerateCredentials");
			hr = this->_EnumerateCredentials();
			g_log.Write("DEBUG: _EnumerateCredentials returned: 0x%08X", hr);
			break;

		case CPUS_CHANGE_PASSWORD:
			g_log.Write("DEBUG: CHANGE_PASSWORD scenario not implemented");
			hr = E_NOTIMPL;
			break;

		default:
			g_log.Write("DEBUG: Unknown scenario - returning E_INVALIDARG");
			hr = E_INVALIDARG;
			break;
	}

	g_log.Write("DEBUG: SetUsageScenario returning: 0x%08X", hr);
	return hr;
}

STDMETHODIMP RdpProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
	g_log.Write("RdpProvider::SetSerialization");

	if (CLSID_RdpProvider != pcpcs->clsidCredentialProvider)
	{
		return E_INVALIDARG;
	}

	ULONG ulAuthPackage;
	HRESULT hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
	if (FAILED(hr))
	{
		return E_INVALIDARG;
	}

	if (ulAuthPackage != pcpcs->ulAuthenticationPackage || 
		pcpcs->cbSerialization == 0 || 
		pcpcs->rgbSerialization == nullptr)
	{
		return E_INVALIDARG;
	}

	KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;
	if (KerbInteractiveLogon != pkil->Logon.MessageType)
	{
		return E_INVALIDARG;
	}

	BYTE* rgbSerialization = (BYTE*)HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
	if (!rgbSerialization)
	{
		return E_OUTOFMEMORY;
	}

	CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
	KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization);

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

	_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization;
	return S_OK;
}

HRESULT RdpProvider::Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
	g_log.Write("DEBUG: Advise called - setting up event callbacks");
	g_log.Write("DEBUG: ICredentialProviderEvents pointer: %p, AdviseContext: %llu", pcpe, upAdviseContext);

	if (_pCredentialProviderEvents)
	{
		g_log.Write("DEBUG: Releasing existing credential provider events");
		_pCredentialProviderEvents->Release();
	}

	_pCredentialProviderEvents = pcpe;
	_pCredentialProviderEvents->AddRef();
	_upAdviseContext = upAdviseContext;

	g_log.Write("DEBUG: Event callbacks set up successfully");

	// Try to connect to desktop client (non-blocking)
	g_log.Write("DEBUG: Attempting initial connection to desktop client");
	HRESULT hrConnect = _ConnectToDesktopClient();
	g_log.Write("DEBUG: Initial connection attempt result: 0x%08X", hrConnect);
	
	// Start a background thread to continuously check for messages
	// This ensures we receive trigger messages even when GetCredentialCount isn't called frequently
	g_log.Write("DEBUG: Starting background message checking thread");
	HRESULT hrThread = _StartBackgroundMessageThread();
	if (FAILED(hrThread))
	{
		g_log.Write("WARNING: Failed to start background message thread - error: 0x%08X", hrThread);
		// Continue anyway as this is not critical for basic functionality
	}
	
	g_log.Write("DEBUG: Advise completed - continuous message checking active");

	return S_OK;
}

HRESULT RdpProvider::UnAdvise()
{
	g_log.Write("DEBUG: UnAdvise called - stopping background thread");

	_StopBackgroundMessageThread();
	_DisconnectFromDesktopClient();

	if (_pCredentialProviderEvents)
	{
		_pCredentialProviderEvents->Release();
		_pCredentialProviderEvents = NULL;
	}

	g_log.Write("DEBUG: UnAdvise completed");
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
	// ALWAYS return 1 credential
	*pdwCount = 1;
	*pdwDefault = 0;
	*pbAutoLogonWithDefault = HasStoredCredentials();

	return hr;
}

HRESULT RdpProvider::GetCredentialAt(DWORD dwIndex, __out ICredentialProviderCredential** ppcpc)
{
	HRESULT hr;

	if (dwIndex >= 1 || !ppcpc) // We always have exactly 1 credential
	{
		return E_INVALIDARG;
	}

	// Check if we have new credentials that require updating the credential tile
	// This allows dynamic credential updates without touching _rgpCredentials from background thread
	const auto storedCreds = GetStoredCredentials();
	bool needsUpdate = false;

	if (!_rgpCredentials[0])
	{
		// No credential object exists yet, create one
		needsUpdate = true;
		g_log.Write("DEBUG: GetCredentialAt - no existing credential, creating new one");
	}
	else if (storedCreds)
	{
		// We have stored credentials, check if credential object needs updating
		// For simplicity, we'll recreate the credential when we have new stored credentials
		// A more sophisticated approach would track if credentials actually changed
		needsUpdate = true;
		g_log.Write("DEBUG: GetCredentialAt - stored credentials available, updating credential object");
	}

	if (needsUpdate)
	{
		// Clean up existing credential
		if (_rgpCredentials[0])
		{
			_rgpCredentials[0]->Release();
			_rgpCredentials[0] = NULL;
		}

		// Create new credential with current stored credentials
		RdpCredential* ppc = new RdpCredential();

		LPCWSTR pwzUser = L"";
		LPCWSTR pwzPassword = L"";
		LPCWSTR pwzDomain = L"";

		if (storedCreds)
		{
			pwzUser = storedCreds->username.c_str();
			pwzPassword = storedCreds->password.c_str();
			pwzDomain = storedCreds->domain.c_str();
			g_log.Write("DEBUG: GetCredentialAt - using stored credentials for new credential object");
		}
		else
		{
			g_log.Write("DEBUG: GetCredentialAt - creating placeholder credential object");
		}

		hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, 
			pwzUser, pwzPassword, pwzDomain);

		if (FAILED(hr))
		{
			ppc->Release();
			return hr;
		}

		_rgpCredentials[0] = ppc;
		_dwNumCreds = 1;
		g_log.Write("DEBUG: GetCredentialAt - created fresh credential object");
	}

	// Return the credential object
	hr = _rgpCredentials[0]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
	return hr;
}

HRESULT RdpProvider::_EnumerateCredentials()
{
    g_log.Write("DEBUG: _EnumerateCredentials called - initializing credential provider");

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

	// Set up for one credential slot - GetCredentialAt will create the actual credential object
	// when Windows requests it, ensuring it has the most current stored credentials
	_dwNumCreds = 1;
	_rgpCredentials[0] = NULL; // Will be created lazily in GetCredentialAt
	
	g_log.Write("DEBUG: _EnumerateCredentials completed - prepared for 1 credential (lazy creation)");
    return S_OK;
}

HRESULT RdpProvider_CreateInstance(REFIID riid, __deref_out void** ppv)
{
	RdpProvider* pProvider = new RdpProvider();
	HRESULT hr = pProvider->QueryInterface(riid, ppv);
	pProvider->Release();
	return hr;
}

HRESULT RdpProvider::_EnumerateSetSerialization()
{
	KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;

	g_log.Write("RdpProvider::_EnumerateSetSerialization");

	_bAutoSubmitSetSerializationCred = false;

	if (_bRemoteOnly && !GetSystemMetrics(SM_REMOTESESSION)) 
	{
		return E_FAIL;
	}

	WCHAR wszUsername[MAX_PATH] = { 0 };
	WCHAR wszPassword[MAX_PATH] = { 0 };

	HRESULT hr = StringCbCopyNW(wszUsername, sizeof(wszUsername), pkil->UserName.Buffer, pkil->UserName.Length);
	if (FAILED(hr))
	{
		return hr;
	}

	hr = StringCbCopyNW(wszPassword, sizeof(wszPassword), pkil->Password.Buffer, pkil->Password.Length);
	if (FAILED(hr))
	{
		return hr;
	}

	RdpCredential* pCred = new RdpCredential();
	hr = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, wszUsername, wszPassword);
	if (FAILED(hr))
	{
		delete pCred;
		return hr;
	}

	_rgpCredentials[_dwNumCreds] = pCred;
	_dwSetSerializationCred = _dwNumCreds;
	_dwNumCreds++;

	if (wcslen(wszPassword) > 0)
	{
		_bAutoSubmitSetSerializationCred = true;
	}

	return S_OK;
}

HRESULT RdpProvider::_ConnectToDesktopClient()
{
	g_log.Write("DEBUG: _ConnectToDesktopClient called - current pipe handle: %p", _hPipe);

	if (_hPipe != INVALID_HANDLE_VALUE)
	{
		g_log.Write("DEBUG: Already connected to desktop client pipe");
		return S_OK; // Already connected
	}

	g_log.Write("DEBUG: Attempting to connect to named pipe: \\\\.\\pipe\\Lanpartyseating.Desktop");

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
		g_log.Write("DEBUG: Failed to connect to desktop client pipe. Error: %d (%s)", 
			dwError, 
			dwError == ERROR_FILE_NOT_FOUND ? "FILE_NOT_FOUND - service not running" :
			dwError == ERROR_PIPE_BUSY ? "PIPE_BUSY - service busy" :
			dwError == ERROR_ACCESS_DENIED ? "ACCESS_DENIED - permission issue" : "OTHER");
		return HRESULT_FROM_WIN32(dwError);
	}

	g_log.Write("DEBUG: Successfully connected to desktop client pipe - handle: %p", _hPipe);

	// Send a registration message so the desktop client knows we're here
	std::string registerMessage = _BuildCredentialProviderConnectedMessage();
	g_log.Write("DEBUG: Sending registration message: %s", registerMessage.c_str());

	DWORD bytesWritten;
	BOOL writeResult = WriteFile(_hPipe, registerMessage.c_str(), (DWORD)registerMessage.length(), &bytesWritten, NULL);

	if (writeResult)
	{
		g_log.Write("DEBUG: Successfully sent registration message - %d bytes written", bytesWritten);
	}
	else
	{
		DWORD dwError = GetLastError();
		g_log.Write("ERROR: Failed to send registration message - error: %d", dwError);
	}

	return S_OK;
}

void RdpProvider::_DisconnectFromDesktopClient()
{
	g_log.Write("DEBUG: _DisconnectFromDesktopClient called - current pipe handle: %p", _hPipe);

	if (_hPipe != INVALID_HANDLE_VALUE)
	{
		g_log.Write("DEBUG: Closing pipe handle");
		CloseHandle(_hPipe);
		_hPipe = INVALID_HANDLE_VALUE;
		g_log.Write("DEBUG: Pipe handle closed and set to INVALID_HANDLE_VALUE");
	}
	else
	{
		g_log.Write("DEBUG: Pipe handle was already INVALID_HANDLE_VALUE - nothing to close");
	}	
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
			HRESULT hr = _ConnectToDesktopClient();
			if (FAILED(hr))
			{
				g_log.Write("DEBUG: Periodic reconnection attempt failed - error: 0x%08X", hr);
			}
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
	
	// Security check: limit maximum message size to prevent DoS
	if (bytesAvailable > MAX_RESPONSE_SIZE)
	{
		g_log.Write("ERROR: Incoming message size (%d bytes) exceeds maximum allowed (%d bytes), disconnecting", bytesAvailable, MAX_RESPONSE_SIZE);
		_DisconnectFromDesktopClient();
		return;
	}
	
	// Use fixed-size buffer to avoid allocation based on untrusted data
	const DWORD BUFFER_SIZE = 4096; // 4KB fixed buffer
	std::vector<char> buffer;
	buffer.reserve(bytesAvailable + 1); // Reserve space but don't allocate yet
	
	DWORD totalBytesRead = 0;
	DWORD bytesRead = 0;
	
	// Read data in chunks to avoid large allocations from untrusted bytesAvailable
	while (totalBytesRead < bytesAvailable)
	{
		char tempBuffer[BUFFER_SIZE];
		DWORD bytesToRead = min(BUFFER_SIZE, bytesAvailable - totalBytesRead);
		
		BOOL result = ReadFile(_hPipe, tempBuffer, bytesToRead, &bytesRead, NULL);
		
		if (!result || bytesRead == 0)
		{
			DWORD dwError = GetLastError();
			g_log.Write("ERROR: Failed to read from pipe - error: %d", dwError);
			return;
		}
		
		// Append to our buffer
		buffer.insert(buffer.end(), tempBuffer, tempBuffer + bytesRead);
		totalBytesRead += bytesRead;
		
		// Safety check: if we've read more than expected, something is wrong
		if (totalBytesRead > bytesAvailable)
		{
			g_log.Write("ERROR: Read more bytes than expected, disconnecting");
			_DisconnectFromDesktopClient();
			return;
		}
	}
	
	// Ensure null termination
	buffer.push_back('\0');

	buffer[bytesRead] = '\0';
	g_log.Write("Received message from desktop client: %s", buffer.data());

	// Parse the trigger login message using proper JSON parsing
	try 
	{
		nlohmann::json message = nlohmann::json::parse(buffer.data());
		std::string messageType = message.value("$type", "");
		
		// Case-insensitive comparison for message type
		std::transform(messageType.begin(), messageType.end(), messageType.begin(), ::tolower);
		
		if (messageType != "triggerloginrequest")
		{
			return; // Not a trigger login request, ignore
		}

		g_log.Write("Processing TriggerLoginRequest with embedded credentials");
		
		// Extract credentials directly from the trigger message
		std::string username = message.value("Username", "");
		std::string password = message.value("Password", "");
		std::string domain = "";
		
		// Handle domain field which can be null in JSON
		if (message.contains("Domain") && !message["Domain"].is_null())
		{
			domain = message["Domain"].get<std::string>();
		}
		
		if (username.empty())
		{
			g_log.Write("ERROR: TriggerLoginRequest missing username");
			return;
		}
		
		g_log.Write("Received credentials in trigger message - Username: %s, Domain: %s, Password length: %zu", 
			username.c_str(), domain.empty() ? "local" : domain.c_str(), password.length());
		

		// Store credentials using modern approach
		StoreCredentials(toWideString(username), toWideString(password), toWideString(domain));
		g_log.Write("Successfully stored credentials from trigger message");
		
		// Don't update _rgpCredentials from background thread - GetCredentialAt will handle
		// creating fresh credential objects when Windows queries after CredentialsChanged

		// Notify Windows that credentials have changed
		if (!_pCredentialProviderEvents)
		{
			g_log.Write("WARNING: No credential provider events available to notify of changes");
			return;
		}

		_pCredentialProviderEvents->CredentialsChanged(_upAdviseContext);
		g_log.Write("Notified Windows of credential changes");
	}
	catch (const nlohmann::json::exception& e)
	{
		g_log.Write("ERROR: Failed to parse JSON message: %s", e.what());
		g_log.Write("The json that failed to parse: %s", buffer.data());
	}

	// std::vector automatically cleans up memory when it goes out of scope
}

// JSON Message builders for strongly typed communication with C# desktop client
std::string RdpProvider::_BuildCredentialProviderConnectedMessage()
{
	nlohmann::json message;
	message["$type"] = "credentialproviderconnected";
	message["ProcessId"] = GetCurrentProcessId();
	message["Timestamp"] = GetTickCount64();
	return message.dump();
}

HRESULT RdpProvider::_StartBackgroundMessageThread()
{
	g_log.Write("DEBUG: _StartBackgroundMessageThread called");
	
	if (_bThreadRunning)
	{
		g_log.Write("DEBUG: Background thread already running");
		return S_OK;
	}

	// Create stop event
	_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!_hStopEvent)
	{
		DWORD error = GetLastError();
		g_log.Write("ERROR: Failed to create stop event for background thread - error: %d", error);
		return HRESULT_FROM_WIN32(error);
	}

	// Create background thread
	_hMessageThread = CreateThread(NULL, 0, _BackgroundMessageThreadProc, this, 0, NULL);
	if (!_hMessageThread)
	{
		DWORD error = GetLastError();
		g_log.Write("ERROR: Failed to create background message thread - error: %d", error);
		CloseHandle(_hStopEvent);
		_hStopEvent = NULL;
		return HRESULT_FROM_WIN32(error);
	}

	_bThreadRunning = true;
	g_log.Write("DEBUG: Background message thread started successfully");
	return S_OK;
}

void RdpProvider::_StopBackgroundMessageThread()
{
	g_log.Write("DEBUG: _StopBackgroundMessageThread called");
	
	if (!_bThreadRunning)
	{
		g_log.Write("DEBUG: Background thread not running");
		return;
	}

	_bThreadRunning = false;

	// Signal stop event
	if (_hStopEvent)
	{
		g_log.Write("DEBUG: Signaling stop event");
		SetEvent(_hStopEvent);
	}

	// Wait for thread to terminate
	if (_hMessageThread)
	{
		g_log.Write("DEBUG: Waiting for background thread to terminate");
		WaitForSingleObject(_hMessageThread, 5000); // 5 second timeout
		CloseHandle(_hMessageThread);
		_hMessageThread = NULL;
		g_log.Write("DEBUG: Background thread terminated");
	}

	// Clean up stop event
	if (_hStopEvent)
	{
		CloseHandle(_hStopEvent);
		_hStopEvent = NULL;
	}

	g_log.Write("DEBUG: Background message thread stopped");
}

DWORD WINAPI RdpProvider::_BackgroundMessageThreadProc(LPVOID lpParam)
{
	RdpProvider* pProvider = static_cast<RdpProvider*>(lpParam);
	
	g_log.Write("DEBUG: Background message thread started");

	// Try to establish initial connection to desktop client
	if (pProvider->_hPipe == INVALID_HANDLE_VALUE)
	{
		g_log.Write("DEBUG: Background thread attempting initial connection");
		HRESULT hr = pProvider->_ConnectToDesktopClient();
		if (FAILED(hr))
		{
			g_log.Write("DEBUG: Background thread initial connection failed - error: 0x%08X", hr);
		}
	}

	while (pProvider->_bThreadRunning)
	{
		// Check for messages (this will handle reconnection if needed)
		pProvider->_CheckForIncomingMessages();

		// Wait for stop event or timeout (1 second polling interval)
		DWORD waitResult = WaitForSingleObject(pProvider->_hStopEvent, 1000);
		if (waitResult == WAIT_OBJECT_0)
		{
			g_log.Write("DEBUG: Background thread received stop signal");
			break;
		}
		// WAIT_TIMEOUT is expected and means continue polling
	}

	g_log.Write("DEBUG: Background message thread exiting");
	return 0;
}

// Helper functions for credential storage refactoring
bool RdpProvider::HasStoredCredentials() const
{
	return _storedCredentials.get() != nullptr;
}

void RdpProvider::StoreCredentials(std::wstring&& username, std::wstring&& password, std::wstring&& domain)
{
	_storedCredentials = std::make_shared<StoredCredentials>(StoredCredentials{ std::move(username), std::move(password), std::move(domain) });
}

void RdpProvider::ClearCredentials()
{
	_storedCredentials.reset();
}

std::shared_ptr<StoredCredentials> RdpProvider::GetStoredCredentials() const
{
	return _storedCredentials;
}

std::wstring RdpProvider::toWideString(std::string_view str) const {
	size_t size = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), NULL, 0);
	if (size == 0) {
		DWORD error = GetLastError();
		g_log.Write("ERROR: Failed to calculate buffer size for UTF-8 to UTF-16 conversion. Input length: %zu, Error: %d", str.size(), error);
		return L"this shit is broken";
	}
	
	std::wstring wstr(size, L'\0'); // Preallocate size
	size_t converted = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), wstr.data(), static_cast<int>(size));
	
	if (converted == 0) {
		DWORD error = GetLastError();
		g_log.Write("ERROR: Failed to convert UTF-8 string to UTF-16. Input length: %zu, Expected output size: %zu, Error: %d", str.size(), size, error);
		return L"this shit is broken";
	}

	if (converted != size) {
		g_log.Write("WARNING: UTF-8 to UTF-16 conversion size mismatch. Expected: %zu, Actual: %zu", size, converted);
	}
	
	return wstr;
}
