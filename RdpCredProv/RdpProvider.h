
#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include <optional>
#include <string>
#include <stdexcept>
#include <memory>


#include "RdpCredential.h"
#include "helpers.h"

#define MAX_CREDENTIALS		1
#define MAX_DWORD		0xFFFFFFFF

// Structure to hold stored credentials
struct StoredCredentials
{
	std::wstring username;
	std::wstring password;
	std::wstring domain;
};

class RdpProvider : public ICredentialProvider
{
public:
	// IUnknown
	STDMETHOD_(ULONG, AddRef)()
	{
		return _cRef++;
	}

	STDMETHOD_(ULONG, Release)()
	{
		LONG cRef = _cRef--;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
	{
		HRESULT hr;
		if (IID_IUnknown == riid || IID_ICredentialProvider == riid)
		{
			*ppv = this;
			reinterpret_cast<IUnknown*>(*ppv)->AddRef();
			hr = S_OK;
		}
		else
		{
			*ppv = NULL;
			hr = E_NOINTERFACE;
		}
		return hr;
	}

public:
	IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
	IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

	IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
	IFACEMETHODIMP UnAdvise();

	IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
	IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

	IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount, __out DWORD* pdwDefault, __out BOOL* pbAutoLogonWithDefault);
	IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, __out ICredentialProviderCredential** ppcpc);

	friend HRESULT RdpProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

protected:
	RdpProvider();
	__override ~RdpProvider();

private:
	HRESULT _EnumerateSetSerialization();
	HRESULT _EnumerateCredentials();
	void _CleanupSetSerialization();
	HRESULT _ConnectToDesktopClient();
	void _DisconnectFromDesktopClient();
	void _CheckForIncomingMessages();
	HRESULT _StartBackgroundMessageThread();
	void _StopBackgroundMessageThread();
	static DWORD WINAPI _BackgroundMessageThreadProc(LPVOID lpParam);
	
	// JSON Message builders for strongly typed communication
	std::string _BuildCredentialProviderConnectedMessage();
	
	// Helper functions for credential storage refactoring
	bool HasStoredCredentials() const;
	// rvalue reference to ensure we don't accidentally make copies
	void StoreCredentials(std::wstring&& username, std::wstring&& password, std::wstring&& domain);
	void ClearCredentials();
	
	// Return reference to stored credentials - throws exception if not available
	std::shared_ptr<StoredCredentials> GetStoredCredentials() const;
	
	// convert std::string to CoTaskMalloc allocated string
	std::wstring toWideString(std::string_view) const;

private:
	LONG _cRef;
	RdpCredential *_rgpCredentials[MAX_CREDENTIALS];
	DWORD _dwNumCreds;
	bool _bLogEnabled;
	bool _bRemoteOnly;
	KERB_INTERACTIVE_UNLOCK_LOGON* _pkiulSetSerialization;
	DWORD _dwSetSerializationCred;
	bool _bAutoSubmitSetSerializationCred;
	bool _bAutoLogonWithDefault;
	bool _bUseDefaultCredentials;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
	
	// Named pipe client to connect to desktop service
	ICredentialProviderEvents* _pCredentialProviderEvents;
	UINT_PTR _upAdviseContext;
	HANDLE _hPipe;
	
	// Stored credentials from desktop client
	std::shared_ptr<StoredCredentials> _storedCredentials;
	
	// Background message checking thread
	HANDLE _hMessageThread;
	HANDLE _hStopEvent;
	bool _bThreadRunning;
};
