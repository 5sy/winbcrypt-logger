#include <windows.h>
#include <stdio.h>

#include "minhook/MinHook.h"

#define PRINT_CONTENTS 1

#define HOOK_FN(mod, name) \
	do {	\
		FARPROC fn_##name = GetProcAddress(mod, #name); \
		if (fn_##name != NULL) { \
			if (MH_CreateHook(fn_##name, &name##_hook, (LPVOID *)&name##_orig) == MH_OK) { \
				printf("Hooked " #name "\n"); \
			} \
		} \
	} while(0);

static BOOL gCalled = FALSE;

typedef NTSTATUS(WINAPI *BCryptAddContextFunction_ptr)(
	ULONG   dwTable,
	LPCWSTR pszContext,
	ULONG   dwInterface,
	LPCWSTR pszFunction,
	ULONG   dwPosition);
static BCryptAddContextFunction_ptr BCryptAddContextFunction_orig;

typedef NTSTATUS(WINAPI *BCryptCloseAlgorithmProvider_ptr)(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
static BCryptCloseAlgorithmProvider_ptr BCryptCloseAlgorithmProvider_orig;

typedef NTSTATUS(WINAPI *BCryptConfigureContext_ptr)(
	IN ULONG                 dwTable,
	IN LPCWSTR               pszContext,
	IN PCRYPT_CONTEXT_CONFIG pConfig);
static BCryptConfigureContext_ptr BCryptConfigureContext_orig;

typedef NTSTATUS(WINAPI *BCryptConfigureContextFunction_ptr)(
	IN ULONG                          dwTable,
	IN LPCWSTR                        pszContext,
	IN ULONG                          dwInterface,
	IN LPCWSTR                        pszFunction,
	IN PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig);
static BCryptConfigureContextFunction_ptr BCryptConfigureContextFunction_orig;

typedef NTSTATUS(WINAPI *BCryptCreateContext_ptr)(
	IN          ULONG                 dwTable,
	IN          LPCWSTR               pszContext,
	IN OPTIONAL PCRYPT_CONTEXT_CONFIG pConfig);
static BCryptCreateContext_ptr BCryptCreateContext_orig;

typedef NTSTATUS(WINAPI *BCryptCreateHash_ptr)(
	IN OUT      BCRYPT_ALG_HANDLE  hAlgorithm,
	OUT         BCRYPT_HASH_HANDLE *phHash,
	OUT         PUCHAR             pbHashObject,
	IN OPTIONAL ULONG              cbHashObject,
	IN OPTIONAL PUCHAR             pbSecret,
	IN          ULONG              cbSecret,
	IN          ULONG              dwFlags);
static BCryptCreateHash_ptr BCryptCreateHash_orig;

typedef NTSTATUS(WINAPI *BCryptCreateMultiHash_ptr)(
	IN OUT BCRYPT_ALG_HANDLE  hAlgorithm,
	OUT    BCRYPT_HASH_HANDLE *phHash,
	IN     ULONG              nHashes,
	OUT    PUCHAR             pbHashObject,
	IN     ULONG              cbHashObject,
	IN     PUCHAR             pbSecret,
	IN     ULONG              cbSecret,
	IN     ULONG              dwFlags);
static BCryptCreateMultiHash_ptr BCryptCreateMultiHash_orig;

typedef NTSTATUS(WINAPI *BCryptDecrypt_ptr)(
	IN OUT           BCRYPT_KEY_HANDLE hKey,
	IN               PUCHAR            pbInput,
	IN               ULONG             cbInput,
	IN OPTIONAL      VOID *pPaddingInfo,
	IN OUT OPTIONAL  PUCHAR            pbIV,
	IN               ULONG             cbIV,
	OUT OPTIONAL     PUCHAR            pbOutput,
	IN               ULONG             cbOutput,
	OUT              ULONG *pcbResult,
	IN               ULONG             dwFlags);
static BCryptDecrypt_ptr BCryptDecrypt_orig;

typedef NTSTATUS(WINAPI *BCryptDeleteContext_ptr)(
	IN ULONG   dwTable,
	IN LPCWSTR pszContext);
static BCryptDeleteContext_ptr BCryptDeleteContext_orig;

typedef NTSTATUS(WINAPI *BCryptDeriveKey_ptr)(
	IN           BCRYPT_SECRET_HANDLE hSharedSecret,
	IN           LPCWSTR              pwszKDF,
	IN OPTIONAL  BCryptBufferDesc *pParameterList,
	OUT OPTIONAL PUCHAR               pbDerivedKey,
	IN           ULONG                cbDerivedKey,
	OUT          ULONG *pcbResult,
	IN           ULONG                dwFlags);
static BCryptDeriveKey_ptr BCryptDeriveKey_orig;

typedef NTSTATUS(WINAPI *BCryptDeriveKeyCapi_ptr)(
	IN          BCRYPT_HASH_HANDLE hHash,
	IN OPTIONAL BCRYPT_ALG_HANDLE  hTargetAlg,
	OUT         PUCHAR             pbDerivedKey,
	IN          ULONG              cbDerivedKey,
	IN          ULONG              dwFlags);
static BCryptDeriveKeyCapi_ptr BCryptDeriveKeyCapi_orig;

typedef NTSTATUS(WINAPI *BCryptDeriveKeyPBKDF2_ptr)(
	IN          BCRYPT_ALG_HANDLE hPrf,
	IN OPTIONAL PUCHAR            pbPassword,
	IN          ULONG             cbPassword,
	IN OPTIONAL PUCHAR            pbSalt,
	IN          ULONG             cbSalt,
	IN          ULONGLONG         cIterations,
	OUT          PUCHAR            pbDerivedKey,
	IN          ULONG             cbDerivedKey,
	IN          ULONG             dwFlags);
static BCryptDeriveKeyPBKDF2_ptr BCryptDeriveKeyPBKDF2_orig;

typedef NTSTATUS(WINAPI *BCryptDestroyHash_ptr)(IN OUT BCRYPT_HASH_HANDLE hHash);
static BCryptDestroyHash_ptr BCryptDestroyHash_orig;

typedef NTSTATUS(WINAPI *BCryptDestroyKey_ptr)(IN OUT BCRYPT_KEY_HANDLE hKey);
static BCryptDestroyKey_ptr BCryptDestroyKey_orig;

typedef NTSTATUS(WINAPI *BCryptDestroySecret_ptr)(IN OUT BCRYPT_SECRET_HANDLE hKey);
static BCryptDestroySecret_ptr BCryptDestroySecret_orig;

typedef NTSTATUS(WINAPI *BCryptDuplicateHash_ptr)(
	IN  BCRYPT_HASH_HANDLE hHash,
	OUT BCRYPT_HASH_HANDLE *phNewHash,
	OUT PUCHAR             pbHashObject,
	IN ULONG              cbHashObject,
	IN ULONG              dwFlags);
static BCryptDuplicateHash_ptr BCryptDuplicateHash_orig;

typedef NTSTATUS(WINAPI *BCryptDuplicateKey_ptr)(
	IN  BCRYPT_KEY_HANDLE hKey,
	OUT BCRYPT_KEY_HANDLE *phNewKey,
	OUT PUCHAR             pbKeyObject,
	IN ULONG              cbKeyObject,
	IN ULONG              dwFlags);
static BCryptDuplicateKey_ptr BCryptDuplicateKey_orig;

typedef NTSTATUS(WINAPI *BCryptEncrypt_ptr)(
	IN OUT           BCRYPT_KEY_HANDLE hKey,
	IN               PUCHAR            pbInput,
	IN               ULONG             cbInput,
	IN OPTIONAL      VOID             *pPaddingInfo,
	IN OUT OPTIONAL  PUCHAR            pbIV,
	IN               ULONG             cbIV,
	OUT OPTIONAL     PUCHAR            pbOutput,
	IN               ULONG             cbOutput,
	OUT              ULONG            *pcbResult,
	IN               ULONG             dwFlags);
static BCryptEncrypt_ptr BCryptEncrypt_orig;

typedef NTSTATUS(WINAPI *BCryptGenerateSymmetricKey_ptr)(
	IN OUT       BCRYPT_ALG_HANDLE hAlgorithm,
	OUT          BCRYPT_KEY_HANDLE *phKey,
	OUT OPTIONAL PUCHAR            pbKeyObject,
	IN           ULONG             cbKeyObject,
	IN           PUCHAR            pbSecret,
	IN           ULONG             cbSecret,
	IN           ULONG             dwFlags);
static BCryptGenerateSymmetricKey_ptr BCryptGenerateSymmetricKey_orig;

typedef NTSTATUS(WINAPI *BCryptSetProperty_ptr)(
	IN OUT BCRYPT_HANDLE hObject,
	IN     LPCWSTR       pszProperty,
	IN     PUCHAR        pbInput,
	IN     ULONG         cbInput,
	IN     ULONG         dwFlags);
static BCryptSetProperty_ptr BCryptSetProperty_orig;

NTSTATUS WINAPI BCryptAddContextFunction_hook(
	IN ULONG   dwTable,
	IN LPCWSTR pszContext,
	IN ULONG   dwInterface,
	IN LPCWSTR pszFunction,
	IN ULONG   dwPosition)
{
	printf(
		"BCryptAddContextFunction(dwTable=%d, pszContext=%S, dwInterface=%d, pszFunction=%S, dwPosition=%d) = ",
		dwTable,
		pszContext,
		dwInterface,
		pszFunction,
		dwPosition
	);

	NTSTATUS res = BCryptAddContextFunction_orig(
		dwTable,
		pszContext,
		dwInterface,
		pszFunction,
		dwPosition
	);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptCloseAlgorithmProvider_hook(IN OUT BCRYPT_ALG_HANDLE hAlgorithm, IN ULONG dwFlags)
{
	printf("BCryptCloseAlgorithmProvider(hAlgorithm=%p, dwFlags=%d) = ", hAlgorithm, dwFlags);

	NTSTATUS res = BCryptCloseAlgorithmProvider_orig(hAlgorithm, dwFlags);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptConfigureContext_hook(
	IN ULONG                 dwTable,
	IN LPCWSTR               pszContext,
	IN PCRYPT_CONTEXT_CONFIG pConfig)
{
	printf("BCryptConfigureContext(dwTable=%d, pszContext=%S) = ", dwTable, pszContext);

	NTSTATUS res = BCryptConfigureContext_orig(
		dwTable,
		pszContext,
		pConfig
	);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptConfigureContextFunction_hook(
	IN ULONG                          dwTable,
	IN LPCWSTR                        pszContext,
	IN ULONG                          dwInterface,
	IN LPCWSTR                        pszFunction,
	IN PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig)
{
	printf(
		"BCryptConfigureContextFunction(dwTable=%d, pszContext=%S, dwInterface=%d, pszFunction=%S) = ",
		dwTable, 
		pszContext, 
		dwInterface,
		pszFunction
	);

	NTSTATUS res = BCryptConfigureContextFunction_orig(
		dwTable,
		pszContext,
		dwInterface,
		pszFunction,
		pConfig
	);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptCreateContext_hook(
	IN          ULONG                 dwTable,
	IN          LPCWSTR               pszContext,
	IN OPTIONAL PCRYPT_CONTEXT_CONFIG pConfig)
{
	printf("BCryptCreateContext(dwTable=%d, pszContext=%S) = ", dwTable, pszContext);

	NTSTATUS res = BCryptCreateContext_orig(dwTable, pszContext, pConfig);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptCreateHash_hook(
	IN OUT      BCRYPT_ALG_HANDLE  hAlgorithm,
	OUT         BCRYPT_HASH_HANDLE *phHash,
	OUT         PUCHAR             pbHashObject,
	IN OPTIONAL ULONG              cbHashObject,
	IN OPTIONAL PUCHAR             pbSecret,
	IN          ULONG              cbSecret,
	IN          ULONG              dwFlags)
{
	printf("BCryptCreateHash(hAlgorithm=%p, cbHashObject=%d, ", hAlgorithm, cbHashObject);

	if (pbSecret != NULL) {
		ULONG i;

		printf("pbSecret=");
		for (i = 0; i < cbSecret; i++) {
			printf("%02X", pbSecret[i]);
		}
		printf("h, cbSecret=%d, ", cbSecret);
	}

	printf("dwFlags=%d) = ", dwFlags);

	NTSTATUS res = BCryptCreateHash_orig(
		hAlgorithm,
		phHash,
		pbHashObject,
		cbHashObject,
		pbSecret,
		cbSecret,
		dwFlags
	);

	printf("(phHash=%p, pbHashObject=%p), %d\n", phHash, pbHashObject, res);

	return res;
}

NTSTATUS WINAPI BCryptCreateMultiHash_hook(
	IN OUT BCRYPT_ALG_HANDLE  hAlgorithm,
	OUT    BCRYPT_HASH_HANDLE *phHash,
	IN     ULONG              nHashes,
	OUT    PUCHAR             pbHashObject,
	IN     ULONG              cbHashObject,
	IN     PUCHAR             pbSecret,
	IN     ULONG              cbSecret,
	IN     ULONG              dwFlags)
{
	printf("BCryptCreateMultiHash(hAlgorithm=%p, nHashes=%d, cbHashObject=%d, ", hAlgorithm, nHashes, cbHashObject);

	if (pbSecret != NULL) {
		ULONG i;

		printf("pbSecret=");
		for (i = 0; i < cbSecret; i++) {
			printf("%02X", pbSecret[i]);
		}
		printf("h, cbSecret=%d, ", cbSecret);
	}

	printf("dwFlags=%d) = ", dwFlags);

	NTSTATUS res = BCryptCreateMultiHash_orig(
		hAlgorithm,
		phHash,
		nHashes,
		pbHashObject,
		cbHashObject,
		pbSecret,
		cbSecret,
		dwFlags
	);

	printf("(phHash=%p, pbHashObject=%p), %d\n", phHash, pbHashObject, res);

	return res;
}

NTSTATUS WINAPI BCryptDecrypt_hook(
	IN OUT           BCRYPT_KEY_HANDLE hKey,
	IN               PUCHAR            pbInput,
	IN               ULONG             cbInput,
	IN OPTIONAL      VOID             *pPaddingInfo,
	IN OUT OPTIONAL  PUCHAR            pbIV,
	IN               ULONG             cbIV,
	OUT OPTIONAL     PUCHAR            pbOutput,
	IN               ULONG             cbOutput,
	OUT              ULONG            *pcbResult,
	IN               ULONG             dwFlags)
{
	ULONG i;

	printf("BCryptDecrypt(hKey=%p, ", hKey);

#ifdef PRINT_CONTENTS
	printf("pbInput=");
	for (i = 0; i < cbInput; i++) {
		printf("%02X", pbInput[i]);
	}
	printf("h, ");
#endif

	printf("cbInput=%d, pPaddingInfo=%p, pbIV=", cbInput, pPaddingInfo);

	if (pbIV != NULL) {
		for (i = 0; i < cbIV; i++) {
			printf("%02X", pbIV[i]);
		}
	}

	printf("h, cbIV=%d, cbOutput=%d, dwFlags=%d) = (", cbIV, cbOutput, dwFlags);

	NTSTATUS res = BCryptDecrypt_orig(
		hKey,
		pbInput,
		cbInput,
		pPaddingInfo,
		pbIV,
		cbIV,
		pbOutput,
		cbOutput,
		pcbResult,
		dwFlags
	);

	if (pbIV != NULL) {
		printf("pbIV=");
		for (i = 0; i < cbIV; i++) {
			printf("%02X", pbIV[i]);
		}
		printf("h, ");
	}

#ifdef PRINT_CONTENTS
	if (pbOutput) {
		printf("pbOutput=");
		for (i = 0; i < cbOutput; i++) {
			printf("%02X", pbOutput[i]);
		}
		printf("h, ");
	}
#endif

	printf("pcbResult=%d), %d\n", *pcbResult, res);

	return res;
}

NTSTATUS WINAPI BCryptDeleteContext_hook(
	IN ULONG   dwTable,
	IN LPCWSTR pszContext) 
{
	printf("BCryptDeleteContext(dwTable=%d, pszContext=%S) = ", dwTable, pszContext);

	NTSTATUS res = BCryptDeleteContext_orig(dwTable, pszContext);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDeriveKey_hook(
	IN           BCRYPT_SECRET_HANDLE hSharedSecret,
	IN           LPCWSTR              pwszKDF,
	IN OPTIONAL  BCryptBufferDesc    *pParameterList,
	OUT OPTIONAL PUCHAR               pbDerivedKey,
	IN           ULONG                cbDerivedKey,
	OUT          ULONG               *pcbResult,
	IN           ULONG                dwFlags)
{
	printf("BCryptDeriveKey(hSharedSecret=%p, pwszKDF=%S, dwFlags=%d) = (", hSharedSecret, pwszKDF, dwFlags);

	NTSTATUS res = BCryptDeriveKey_orig(
		hSharedSecret,
		pwszKDF,
		pParameterList,
		pbDerivedKey,
		cbDerivedKey,
		pcbResult,
		dwFlags
	);

	if (pbDerivedKey != NULL) {
		ULONG i;

		printf("pbDerivedKey=");
		for (i = 0; i < cbDerivedKey; i++) {
			printf("%02X", pbDerivedKey[i]);
		}
		printf("h, ");
	}

	if (pcbResult) {
		printf("pcbResult=%d, ", *pcbResult);
	}

	printf("cbDerivedKey=%d), %d\n", cbDerivedKey, res);

	return res;
}

NTSTATUS WINAPI BCryptDeriveKeyCapi_hook(
	IN          BCRYPT_HASH_HANDLE hHash,
	IN OPTIONAL BCRYPT_ALG_HANDLE  hTargetAlg,
	OUT         PUCHAR             pbDerivedKey,
	IN          ULONG              cbDerivedKey,
	IN          ULONG              dwFlags)
{
	printf("BCryptDeriveKeyCapi(hHash=%p, cbDerivedKey=%d, dwFlags=%d) = (", hHash, cbDerivedKey, dwFlags);

	NTSTATUS res = BCryptDeriveKeyCapi_orig(
		hHash,
		hTargetAlg,
		pbDerivedKey,
		cbDerivedKey,
		dwFlags
	);

	
	printf("pbDerivedKey=");

	ULONG i;
	for (i = 0; i < cbDerivedKey; i++) {
		printf("%02X", pbDerivedKey[i]);
	}

	printf("h), %d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDeriveKeyPBKDF2_hook(
	IN          BCRYPT_ALG_HANDLE hPrf,
	IN OPTIONAL PUCHAR            pbPassword,
	IN          ULONG             cbPassword,
	IN OPTIONAL PUCHAR            pbSalt,
	IN          ULONG             cbSalt,
	IN          ULONGLONG         cIterations,
	OUT         PUCHAR            pbDerivedKey,
	IN          ULONG             cbDerivedKey,
	IN          ULONG             dwFlags)
{
	ULONG i;

	printf("BCryptDeriveKeyPBKDF2(hPrf=%p, ", hPrf);

	if (pbPassword != NULL) {
		printf("pbPassword=");
		for (i = 0; i < cbPassword; i++) {
			printf("%02X", pbPassword[i]);
		}
		printf("h, ");
	}

	printf("cbPassword=%d, ", cbPassword);

	if (pbSalt != NULL) {
		printf("pbSalt=");
		for (i = 0; i < cbSalt; i++) {
			printf("%02X", pbSalt[i]);
		}
		printf("h, ");
	}

	printf("cbSalt=%d, cIterations=%lld, cbDerivedKey=%d, dwFlags=%d) = ", cbSalt, cIterations, cbDerivedKey, dwFlags);

	NTSTATUS res = BCryptDeriveKeyPBKDF2_orig(
		hPrf,
		pbPassword,
		cbPassword,
		pbSalt,
		cbSalt,
		cIterations,
		pbDerivedKey,
		cbDerivedKey,
		dwFlags
	);

	if (pbDerivedKey != NULL) {
		printf("(pbDerivedKey=");
		for (i = 0; i < cbDerivedKey; i++) {
			printf("%02X", pbDerivedKey[i]);
		}
		printf("h), ");
	}

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDestroyHash_hook(IN OUT BCRYPT_HASH_HANDLE hHash) 
{
	printf("BCryptDestroyHash(hHash=%p) = ", hHash);

	NTSTATUS res = BCryptDestroyHash_orig(hHash);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDestroyKey_hook(IN OUT BCRYPT_KEY_HANDLE hKey)
{
	printf("BCryptDestroyKey(hKey=%p) = ", hKey);

	NTSTATUS res = BCryptDestroyKey_orig(hKey);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDestroySecret_hook(IN OUT BCRYPT_SECRET_HANDLE hSecret)
{
	printf("BCryptDestroySecret(hSecret=%p) = ", hSecret);

	NTSTATUS res = BCryptDestroySecret_orig(hSecret);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDuplicateHash_hook(
	IN  BCRYPT_HASH_HANDLE hHash,
	OUT BCRYPT_HASH_HANDLE *phNewHash,
	OUT PUCHAR             pbHashObject,
	IN ULONG              cbHashObject,
	IN ULONG              dwFlags) 
{
	ULONG i;

	printf("BCryptDuplicateHash(hHash=%p, cbHashObject=%d, dwFlags=%d) = ", hHash, cbHashObject, dwFlags);

	NTSTATUS res = BCryptDuplicateHash_orig(
		hHash, 
		phNewHash, 
		pbHashObject,
		cbHashObject,
		dwFlags
	);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptDuplicateKey_hook(
	IN  BCRYPT_KEY_HANDLE hKey,
	OUT BCRYPT_KEY_HANDLE *phNewKey,
	OUT PUCHAR             pbKeyObject,
	IN ULONG              cbKeyObject,
	IN ULONG              dwFlags)
{
	printf("BCryptDuplicateKey(hKey=%p, cbKeyObject=%d, dwFlags=%d) = ", hKey, cbKeyObject, dwFlags);

	NTSTATUS res = BCryptDuplicateKey_orig(
		hKey,
		phNewKey,
		pbKeyObject,
		cbKeyObject,
		dwFlags
	);

	printf("%d\n", res);

	return res;
}

NTSTATUS WINAPI BCryptEncrypt_hook(
	IN OUT           BCRYPT_KEY_HANDLE hKey,
	IN               PUCHAR            pbInput,
	IN               ULONG             cbInput,
	IN OPTIONAL      VOID             *pPaddingInfo,
	IN OUT OPTIONAL  PUCHAR            pbIV,
	IN               ULONG             cbIV,
	OUT OPTIONAL     PUCHAR            pbOutput,
	IN               ULONG             cbOutput,
	OUT              ULONG            *pcbResult,
	IN               ULONG             dwFlags)
{
	ULONG i;

	printf("BCryptEncrypt(hKey=%p, ", hKey);

#ifdef PRINT_CONTENTS
	printf("pbInput=");
	for (i = 0; i < cbInput; i++) {
		printf("%02X", pbInput[i]);
	}
	printf("h, ");
#endif

	printf("cbInput=%d, pPaddingInfo=%p, pbIV=", cbInput, pPaddingInfo);

	if (pbIV != NULL) {
		for (i = 0; i < cbIV; i++) {
			printf("%02X", pbIV[i]);
		}
	}

	printf("h, cbIV=%d, cbOutput=%d, dwFlags=%d) = (", cbIV, cbOutput, dwFlags);

	NTSTATUS res = BCryptEncrypt_orig(
		hKey,
		pbInput,
		cbInput,
		pPaddingInfo,
		pbIV,
		cbIV,
		pbOutput,
		cbOutput,
		pcbResult,
		dwFlags
	);

	if (pbIV != NULL) {
		printf("pbIV=");
		for (i = 0; i < cbIV; i++) {
			printf("%02X", pbIV[i]);
		}
		printf("h, ");
	}

#ifdef PRINT_CONTENTS
	if (pbOutput) {
		printf("pbOutput=");
		for (i = 0; i < cbOutput; i++) {
			printf("%02X", pbOutput[i]);
		}
		printf("h, ");
	}
#endif

	printf("pcbResult=%d), %d\n", *pcbResult, res);

	return res;
}

NTSTATUS WINAPI BCryptSetProperty_hook(
	IN OUT BCRYPT_HANDLE hObject,
	IN     LPCWSTR       pszProperty,
	IN     PUCHAR        pbInput,
	IN     ULONG         cbInput,
	IN     ULONG         dwFlags)
{
	ULONG i;

	printf("BCryptSetProperty(hObject=%p, pszProperty=%S, pbInput=", hObject, pszProperty);

	for (i = 0; i < cbInput; i++) {
		printf("%02X", pbInput[i]);
	}

	printf("h, cbInput=%d, dwFlags=%d) = ", cbInput, dwFlags);

	NTSTATUS res = BCryptSetProperty_orig(
		hObject,
		pszProperty,
		pbInput,
		cbInput,
		dwFlags
	);

	printf("%d\n", res);
	
	return res;
}

NTSTATUS WINAPI BCryptGenerateSymmetricKey_hook(
	IN OUT       BCRYPT_ALG_HANDLE hAlgorithm,
	OUT          BCRYPT_KEY_HANDLE *phKey,
	OUT OPTIONAL PUCHAR            pbKeyObject,
	IN           ULONG             cbKeyObject,
	IN           PUCHAR            pbSecret,
	IN           ULONG             cbSecret,
	IN           ULONG             dwFlags)
{
	ULONG i;

	printf("BCryptGenerateSymmetricKey(hAlgorithm=%p, cbKeyObject=%d, pbSecret=", hAlgorithm, cbKeyObject);

	for (i = 0; i < cbSecret; i++) {
		printf("%02X", pbSecret[i]);
	}

	printf("h, cbSecret=%d, dwFlags=%d) = (pbKeyObject=", cbSecret, dwFlags);

	NTSTATUS res = BCryptGenerateSymmetricKey_orig(
		hAlgorithm,
		phKey,
		pbKeyObject,
		cbKeyObject,
		pbSecret,
		cbSecret,
		dwFlags
	);

	for (i = 0; i < cbKeyObject; i++) {
		printf("%02X", pbKeyObject[i]);
	}

	printf("h, phKey=%p), %d\n", phKey, res);

	return res;

}

void unload() {
	MH_Uninitialize();
	FreeConsole();
	gCalled = FALSE;
}

void load() 
{
	if (gCalled == TRUE) {
		return;
	}

	//AllocConsole();

	//FILE *fDummy;
	//freopen_s(&fDummy, "CONIN$", "r", stdin);
	//freopen_s(&fDummy, "CONOUT$", "w", stderr);
	//freopen_s(&fDummy, "CONOUT$", "w", stdout);

	if (MH_Initialize() != MH_OK) {
		fprintf(stderr, "Failed to init minhook\n");
		unload();
		return;
	}

	HMODULE mod = GetModuleHandle(L"Bcrypt.dll");
	if (mod == NULL) {
		fprintf(stderr, "Bcrypt.dll == NULL\n");
		unload();
		return;
	}

	HOOK_FN(mod, BCryptAddContextFunction);
	HOOK_FN(mod, BCryptCloseAlgorithmProvider);
	HOOK_FN(mod, BCryptConfigureContext);
	HOOK_FN(mod, BCryptConfigureContextFunction);
	HOOK_FN(mod, BCryptCreateContext);
	HOOK_FN(mod, BCryptCreateHash);
	HOOK_FN(mod, BCryptCreateMultiHash);
	HOOK_FN(mod, BCryptDecrypt);
	HOOK_FN(mod, BCryptDeleteContext);
	HOOK_FN(mod, BCryptDeriveKey);
	HOOK_FN(mod, BCryptDeriveKeyCapi);
	HOOK_FN(mod, BCryptDeriveKeyPBKDF2);
	HOOK_FN(mod, BCryptDestroyHash);
	HOOK_FN(mod, BCryptDestroyKey);
	HOOK_FN(mod, BCryptDestroySecret);
	HOOK_FN(mod, BCryptDuplicateHash);
	HOOK_FN(mod, BCryptDuplicateKey);
	HOOK_FN(mod, BCryptEncrypt);
	//HOOK_FN(mod, BCryptEnumAlgorithms);
	//HOOK_FN(mod, BCryptEnumContextFunctionProviders);
	//HOOK_FN(mod, BCryptEnumContextFunctions);
	//HOOK_FN(mod, BCryptEnumContexts);
	//HOOK_FN(mod, BCryptEnumProviders);
	//HOOK_FN(mod, BCryptEnumRegisteredProviders);
	//HOOK_FN(mod, BCryptExportKey);
	//HOOK_FN(mod, BCryptFinalizeKeyPair);
	//HOOK_FN(mod, BCryptFinishHash);
	//HOOK_FN(mod, BCryptFreeBuffer);
	//HOOK_FN(mod, BCryptGenerateKeyPair);
	HOOK_FN(mod, BCryptGenerateSymmetricKey);
	//HOOK_FN(mod, BCryptGenRandom);
	//HOOK_FN(mod, BCryptGetFipsAlgorithmMode);
	//HOOK_FN(mod, BCryptGetProperty);
	//HOOK_FN(mod, BCryptHash);
	//HOOK_FN(mod, BCryptHashData);
	//HOOK_FN(mod, BCryptImportKey);
	//HOOK_FN(mod, BCryptImportKeyPair);
	//HOOK_FN(mod, BCryptKeyDerivation);
	//HOOK_FN(mod, BCryptOpenAlgorithmProvider);
	//HOOK_FN(mod, BCryptProcessMultiOperations);
	//HOOK_FN(mod, BCryptQueryContextConfiguration);
	//HOOK_FN(mod, BCryptQueryContextFunctionConfiguration);
	//HOOK_FN(mod, BCryptQueryContextFunctionProperty);
	//HOOK_FN(mod, BCryptQueryProviderRegistration);
	//HOOK_FN(mod, BCryptRegisterConfigChangeNotify);
	//HOOK_FN(mod, BCryptRemoveContextFunction);
	//HOOK_FN(mod, BCryptResolveProviders);
	//HOOK_FN(mod, BCryptSecretAgreement);
	//HOOK_FN(mod, BCryptSetContextFunctionProperty);
	HOOK_FN(mod, BCryptSetProperty);
	//HOOK_FN(mod, BCryptSignHash);
	//HOOK_FN(mod, BCryptUnregisterConfigChangeNotify);
	//HOOK_FN(mod, BCryptVerifySignature);

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		fprintf(stderr, "Failed to enable hooks\n");
		unload();
		return;
	}

	printf("Hooked\n");

	gCalled = TRUE;
}

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason, 
	LPVOID lpvReserved)
{
	switch (fdwReason) 
	{
		case DLL_PROCESS_ATTACH:
			load();
			break;

		case DLL_PROCESS_DETACH:
			unload();
			break;

		default:
			break;
	}

	return TRUE;
}
