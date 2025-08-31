
#pragma once
#include <strsafe.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
#include <shlguid.h>

#define RDPCREDPROV_REGPATH	L"SOFTWARE\\Devolutions\\RdpCredProv"

enum SAMPLE_FIELD_ID 
{
	SFI_TILEIMAGE = 0,
	SFI_MAIN_TEXT = 1,
	SFI_HELP_TEXT = 2,
	SFI_USERNAME = 3,
	SFI_PASSWORD = 4,
	SFI_SUBMIT_BUTTON = 5,
	SFI_NUM_FIELDS = 6,
};

struct FIELD_STATE_PAIR
{
	CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },        // Tile image
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },        // Main text
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },        // Help text
	{ CPFS_HIDDEN, CPFIS_NONE },                 // Username (hidden)
	{ CPFS_HIDDEN, CPFIS_NONE },                 // Password (hidden)
	{ CPFS_HIDDEN, CPFIS_NONE },                 // Submit button (hidden)
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
	{ SFI_TILEIMAGE, CPFT_TILE_IMAGE, L"Otakuthon PC Gaming", CPFG_CREDENTIAL_PROVIDER_LOGO },
	{ SFI_MAIN_TEXT, CPFT_LARGE_TEXT, L"Otakuthon PC Gaming Login", CPFG_CREDENTIAL_PROVIDER_LABEL },
	{ SFI_HELP_TEXT, CPFT_SMALL_TEXT, L"Hold your badge near the scanner at the entrance to sign in", CPFG_CREDENTIAL_PROVIDER_LABEL },
	{ SFI_USERNAME, CPFT_EDIT_TEXT, L"User name", CPFG_LOGON_USERNAME },
	{ SFI_PASSWORD, CPFT_PASSWORD_TEXT, L"Password", CPFG_LOGON_PASSWORD },
	{ SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit", CPFG_CREDENTIAL_PROVIDER_LABEL },
};
