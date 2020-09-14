#include <windows.h>
#include <iostream>
#include <mutex>

typedef int(__cdecl* napi_typeof_t)(uintptr_t env, uintptr_t, uintptr_t);
typedef int(__cdecl* napi_run_script_t)(uintptr_t env, uintptr_t script, uintptr_t* result_out);
typedef int(__cdecl* napi_create_string_utf8_t)(uintptr_t env, const char*, size_t, uintptr_t* result_out);

HMODULE this_module;
napi_run_script_t napi_run_script = nullptr;
napi_create_string_utf8_t napi_create_string_utf8 = nullptr;
std::once_flag hook_executed{};
BYTE original_bytes[5] = {};
uintptr_t napi_typeof;
uint32_t prime = 0x01000193, seed = 0x811C9DC5;

uintptr_t place_hook(uintptr_t address, void* hook)
{
	auto hook_instructions = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, 32, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	memcpy(hook_instructions, (void*)address, 5);
	unsigned char jump[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*reinterpret_cast<uintptr_t*>(jump + 1) = ((address + 5) - (reinterpret_cast<uintptr_t>(hook_instructions) + 5)) - 5;
	memcpy(hook_instructions + 5, jump, sizeof(jump));

	DWORD orig_protection;
	VirtualProtect(reinterpret_cast<LPVOID>(address), 5, PAGE_EXECUTE_READWRITE, &orig_protection);
	*reinterpret_cast<BYTE*>(address) = 0xE9;
	*reinterpret_cast<uintptr_t*>(address + 1) = (reinterpret_cast<uintptr_t>(hook) - address) - 5;
	VirtualProtect((LPVOID)address, 5, orig_protection, NULL);

	return reinterpret_cast<uintptr_t>(hook_instructions);
}

inline uint32_t fnv1a(unsigned char one_byte, uint32_t hash = seed)
{
	return (one_byte ^ hash) * prime;
}

uint32_t fnv1a(const char* text, uint32_t hash = seed)
{
	while (*text)
		hash = fnv1a(static_cast<unsigned char>(*text++), hash); 
	return hash;
}

#define RESOLVE_REL_CALC(x,y) ((LPBYTE)x + y)
uintptr_t find_by_hash(HMODULE hLibrary, uint32_t hash)
{
	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)hLibrary;
	if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)RESOLVE_REL_CALC(hLibrary, pDOSHdr->e_lfanew);
	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	if (pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		return FALSE;

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)RESOLVE_REL_CALC(hLibrary,
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddress = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfFunctions);
	PDWORD pdwNames = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNames);
	PWORD pwOrd = (PWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
	{
		UINT32 u32FuncHash = fnv1a((LPCSTR)RESOLVE_REL_CALC(hLibrary, pdwNames[i]));
		if (u32FuncHash == hash)
			return (DWORD)RESOLVE_REL_CALC(hLibrary, pdwAddress[pwOrd[i]]);
	}

	return FALSE;
}

napi_typeof_t napi_typeof_orig;
int __cdecl napi_typeof_hook(uintptr_t env, uintptr_t a2, uintptr_t a3)
{
	std::call_once(hook_executed, [=]()
	{
		const char* script_to_run = "console.log(\"hi\");";
		
		uintptr_t script, result;
		napi_create_string_utf8(env, script_to_run, strlen(script_to_run), &script);
		napi_run_script(env, script, &result);

		// unhook
		DWORD orig_protection;
		VirtualProtect(reinterpret_cast<LPVOID>(napi_typeof), 5, PAGE_EXECUTE_READWRITE, &orig_protection);
		memcpy(reinterpret_cast<void*>(napi_typeof), original_bytes, 5);
		VirtualProtect(reinterpret_cast<LPVOID>(napi_typeof), 5, orig_protection, NULL);

		CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(FreeLibraryAndExitThread), this_module, NULL, NULL);
	});
	return napi_typeof_orig(env, a2, a3);
}

DWORD __stdcall init_thread(LPVOID)
{
	auto mod = GetModuleHandleA(NULL);

	napi_run_script = reinterpret_cast<napi_run_script_t>(find_by_hash(mod, 0x6a771899));
	napi_create_string_utf8 = reinterpret_cast<napi_create_string_utf8_t>(find_by_hash(mod, 0x5c50f322));
	napi_typeof = find_by_hash(mod, 0xd60363c5);

	if (napi_run_script == NULL || napi_create_string_utf8 == NULL || napi_typeof == NULL)
	{
		CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(FreeLibraryAndExitThread), this_module, NULL, NULL);
		return 0;
	}

	memcpy(original_bytes, reinterpret_cast<void*>(napi_typeof), 5);
	napi_typeof_orig = reinterpret_cast<napi_typeof_t>(place_hook(napi_typeof, &napi_typeof_hook));
	return 0;
}

BOOL APIENTRY DllMain(HANDLE module, DWORD ul_reason_for_call, LPVOID lp_reserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		this_module = reinterpret_cast<HMODULE>(module);
		if (GetModuleHandleA("discord_dispatch.node") == NULL)
		{
			CreateThread(NULL, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(FreeLibraryAndExitThread), this_module, NULL, NULL);
			return TRUE;
		}
		CreateThread(NULL, NULL, init_thread, NULL, NULL, NULL);
	}
	return TRUE;
}