
#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "RdpCredential.h"
#include "guid.h"

extern CLogFile log;
extern HINSTANCE g_hinst;

RdpCredential::RdpCredential():
	_cRef(1),
	_pCredProvCredentialEvents(NULL),
	_cpus(CPUS_INVALID),
	pwszDomain(nullptr)
{
	DllAddRef();

	ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
	ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
	ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

RdpCredential::~RdpCredential()
{
	// Securely clear password field if it exists
	if (_rgFieldStrings[SFI_PASSWORD])
	{
		size_t lenPassword;
		HRESULT hr = StringCchLengthW(_rgFieldStrings[SFI_PASSWORD], 128, &(lenPassword));

		if (SUCCEEDED(hr))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
		}
	}

	for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
	{
		CoTaskMemFree(_rgFieldStrings[i]);
		CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
	}

	DllRelease();
}

HRESULT RdpCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	const FIELD_STATE_PAIR* rgfsp, PCWSTR pwzUsername, PCWSTR pwzPassword, PCWSTR pwzDomain)
{
	HRESULT hr = S_OK;

	log.Write("RdpCredential::Initialize");

	_cpus = cpus;

	for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
	{
		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
	}
	
	// Initialize text field strings - extract from the copied field descriptors
	if (SUCCEEDED(hr))
	{
		// Tile image has no string value
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_TILEIMAGE]);
	}
	
	if (SUCCEEDED(hr))
	{
		// Main text field - use the label from the copied field descriptor
		hr = SHStrDupW(_rgCredProvFieldDescriptors[SFI_MAIN_TEXT].pszLabel, &_rgFieldStrings[SFI_MAIN_TEXT]);
	}

	if (SUCCEEDED(hr))
	{
		// Help text field - use the label from the copied field descriptor
		hr = SHStrDupW(_rgCredProvFieldDescriptors[SFI_HELP_TEXT].pszLabel, &_rgFieldStrings[SFI_HELP_TEXT]);
	}

	// Initialize hidden credential fields
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzUsername ? pwzUsername : L"", &_rgFieldStrings[SFI_USERNAME]);
	}
	
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzPassword ? pwzPassword : L"", &_rgFieldStrings[SFI_PASSWORD]);
	}

	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
	}

	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzDomain ? pwzDomain : L"", &pwszDomain);
	}

	return S_OK;
}

HRESULT RdpCredential::UpdateCredentials(PCWSTR pwzUsername, PCWSTR pwzPassword, PCWSTR pwzDomain)
{
	HRESULT hr = S_OK;

	log.Write("DEBUG: RdpCredential::UpdateCredentials called - Username: %ws", pwzUsername ? pwzUsername : L"NULL");

	// Update username
	if (_rgFieldStrings[SFI_USERNAME])
	{
		CoTaskMemFree(_rgFieldStrings[SFI_USERNAME]);
		_rgFieldStrings[SFI_USERNAME] = NULL;
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzUsername ? pwzUsername : L"", &_rgFieldStrings[SFI_USERNAME]);
		if (SUCCEEDED(hr))
		{
			log.Write("DEBUG: Updated username field: %ws", _rgFieldStrings[SFI_USERNAME]);
		}
		else
		{
			log.Write("ERROR: Failed to update username field - HRESULT: 0x%08X", hr);
		}
	}

	// Update password
	if (_rgFieldStrings[SFI_PASSWORD])
	{
		// Securely clear existing password
		size_t lenPassword;
		HRESULT hrLen = StringCchLengthW(_rgFieldStrings[SFI_PASSWORD], 128, &lenPassword);
		if (SUCCEEDED(hrLen))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(WCHAR));
		}
		CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
		_rgFieldStrings[SFI_PASSWORD] = NULL;
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzPassword ? pwzPassword : L"", &_rgFieldStrings[SFI_PASSWORD]);
		if (SUCCEEDED(hr))
		{
			log.Write("DEBUG: Updated password field (length: %zu chars)", pwzPassword ? wcslen(pwzPassword) : 0);
		}
		else
		{
			log.Write("ERROR: Failed to update password field - HRESULT: 0x%08X", hr);
		}
	}

	// Update domain
	if (pwszDomain)
	{
		CoTaskMemFree(pwszDomain);
		pwszDomain = NULL;
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(pwzDomain ? pwzDomain : L"", &pwszDomain);
		if (SUCCEEDED(hr))
		{
			log.Write("DEBUG: Updated domain field: %ws", pwszDomain);
		}
		else
		{
			log.Write("ERROR: Failed to update domain field - HRESULT: 0x%08X", hr);
		}
	}

	log.Write("DEBUG: RdpCredential::UpdateCredentials completed - HRESULT: 0x%08X", hr);
	return hr;
}

HRESULT RdpCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
	log.Write("RdpCredential::Advise");

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}

	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	return S_OK;
}

HRESULT RdpCredential::UnAdvise()
{
	log.Write("RdpCredential::UnAdvise");

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}

	_pCredProvCredentialEvents = NULL;

	return S_OK;
}

HRESULT RdpCredential::SetSelected(BOOL* pbAutoLogon)  
{
	log.Write("RdpCredential::SetSelected");

	*pbAutoLogon = FALSE;

	return S_OK;
}

HRESULT RdpCredential::SetDeselected()
{
	HRESULT hr = S_OK;
	
	log.Write("RdpCredential::SetDeselected");

	if (_rgFieldStrings[SFI_PASSWORD])
	{
		size_t lenPassword;
		hr = StringCchLengthW(_rgFieldStrings[SFI_PASSWORD], 128, &(lenPassword));

		if (SUCCEEDED(hr))
		{
			SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

			CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
		}

		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
		}
	}

	return hr;
}

HRESULT RdpCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
	HRESULT hr;

	log.Write("RdpCredential::GetFieldState");

	if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
	HRESULT hr;

	log.Write("RdpCredential::GetStringValue");

	if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
	{
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
	HRESULT hr;

	log.Write("RdpCredential::GetBitmapValue");

	if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
	{
		HBITMAP hbmp = LoadBitmap(g_hinst, MAKEINTRESOURCE(IDB_TILE_IMAGE));

		if (hbmp != NULL)
		{
			hr = S_OK;
			*phbmp = hbmp;
		}
		else
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
	HRESULT hr;

	log.Write("RdpCredential::GetSubmitButtonValue");

	if ((SFI_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
	{
		*pdwAdjacentTo = SFI_PASSWORD;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
	HRESULT hr;
	PSTR pz = NULL;

	// don't log the value, because it can include typed credentials
	log.Write("RdpCredential::SetStringValue: dwFieldID: %d", (int) dwFieldID);

	if ((dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors)) && 
		(CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
		CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
	{
		PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
		CoTaskMemFree(*ppwszStored);
		hr = SHStrDupW(pwz, ppwszStored);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpCredential::GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pbChecked);
	UNREFERENCED_PARAMETER(ppwszLabel);

	log.Write("RdpCredential::GetCheckboxValue");

	return E_NOTIMPL;
}

HRESULT RdpCredential::GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(pcItems);
	UNREFERENCED_PARAMETER(pdwSelectedItem);

	log.Write("RdpCredential::GetComboBoxValueCount");

	return E_NOTIMPL;
}

HRESULT RdpCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(dwItem);
	UNREFERENCED_PARAMETER(ppwszItem);

	log.Write("RdpCredential::GetComboBoxValueAt");

	return E_NOTIMPL;
}

HRESULT RdpCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);

	log.Write("RdpCredential::SetCheckboxValue");

	return E_NOTIMPL;
}

HRESULT RdpCredential::SetComboBoxSelectedValue(DWORD dwFieldId, DWORD dwSelectedItem)
{
	UNREFERENCED_PARAMETER(dwFieldId);
	UNREFERENCED_PARAMETER(dwSelectedItem);

	log.Write("RdpCredential::SetComboBoxSelectedValue");

	return E_NOTIMPL;
}

HRESULT RdpCredential::CommandLinkClicked(DWORD dwFieldID)
{
	UNREFERENCED_PARAMETER(dwFieldID);

	log.Write("RdpCredential::CommandLinkClicked");

	return E_NOTIMPL;
}

HRESULT RdpCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, PWSTR* ppwszOptionalStatusText,
	CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
	HRESULT hr = S_OK;

	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	log.Write("RdpCredential::GetSerialization");

	// Handle domain field - if empty or null, use local computer name for local logon
	if (!pwszDomain || wcslen(pwszDomain) == 0)
	{
		log.Write("DEBUG: Domain is empty, using local computer name");
		WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD cch = ARRAYSIZE(wsz);

		if (GetComputerNameW(wsz, &cch))
		{
			if (pwszDomain)
			{
				CoTaskMemFree(pwszDomain);
			}
			hr = SHStrDupW(wsz, &pwszDomain);
			log.Write("DEBUG: Set domain to computer name: %ws", pwszDomain);
		}
		else
		{
			log.Write("ERROR: Failed to get computer name, using '.' for local domain");
			if (pwszDomain)
			{
				CoTaskMemFree(pwszDomain);
			}
			hr = SHStrDupW(L".", &pwszDomain);
		}
	}
	else if (!wcscmp(pwszDomain, L"."))
	{
		// Original logic for explicit "." domain
		WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD cch = ARRAYSIZE(wsz);

		if (!GetComputerNameW(wsz, &cch))
		{
			DWORD dwErr = GetLastError();
			hr = HRESULT_FROM_WIN32(dwErr);
			return hr;
		}

		hr = SHStrDupW(wsz ? wsz : L"", &pwszDomain);
	}

	PWSTR pwzProtectedPassword;

	hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);

	if (SUCCEEDED(hr))
	{
		KERB_INTERACTIVE_UNLOCK_LOGON kiul;

		PWSTR pwszUserName = _rgFieldStrings[SFI_USERNAME];

		// Add detailed logging before attempting logon
		log.Write("DEBUG: GetSerialization preparing logon - Username: %ws, Domain: %ws, Password length: %zu", 
			pwszUserName ? pwszUserName : L"NULL",
			pwszDomain ? pwszDomain : L"NULL",
			_rgFieldStrings[SFI_PASSWORD] ? wcslen(_rgFieldStrings[SFI_PASSWORD]) : 0);

		char* pszUserName = NULL;
		char* pszDomain = NULL;

		ConvertFromUnicode(CP_UTF8, 0, pwszUserName, -1, &pszUserName, 0, NULL, NULL);
		ConvertFromUnicode(CP_UTF8, 0, pwszDomain, -1, &pszDomain, 0, NULL, NULL);

		log.Write("KerbInteractiveUnlockLogonInit: UserName: '%s' Domain: '%s'", pszUserName, pszDomain);

		hr = KerbInteractiveUnlockLogonInit(pwszDomain, pwszUserName, pwzProtectedPassword, _cpus, &kiul);

		if (SUCCEEDED(hr))
		{
			hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

			if (SUCCEEDED(hr))
			{
				ULONG ulAuthPackage;
				hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

				if (SUCCEEDED(hr))
				{
					pcpcs->ulAuthenticationPackage = ulAuthPackage;
					pcpcs->clsidCredentialProvider = CLSID_RdpProvider;
					*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
				}
			}
		}

		CoTaskMemFree(pwzProtectedPassword);
	}

	return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
	NTSTATUS ntsStatus;
	NTSTATUS ntsSubstatus;
	PWSTR pwzMessage;
	CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
	{ STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
	{ STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

HRESULT RdpCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
	PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
	*ppwszOptionalStatusText = NULL;
	*pcpsiOptionalStatusIcon = CPSI_NONE;

	DWORD dwStatusInfo = (DWORD)-1;

	log.Write("RdpCredential::ReportResult");

	for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
	{
		if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
		{
			dwStatusInfo = i;
			break;
		}
	}

	if ((DWORD)-1 != dwStatusInfo)
	{
		if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
		{
			*pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
		}
	}

	if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
	{
		if (_pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
		}
	}

	return S_OK;
}
