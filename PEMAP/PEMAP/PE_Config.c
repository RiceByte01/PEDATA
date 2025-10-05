#pragma once
// PE_Config.c
#define _CRT_SECURE_NO_WARNINGS
#include "PE_Config.h"
#include <stdint.h>

// ---------- Helpers ----------
static DWORD FileSizeFromBuffer(PCHAR pFileBuffer) {
    // ���Ŵ� DOS/NT ͷ�� SizeOfHeaders / ����Ϣ�ƶ��ļ���Χ�����ԣ�
    // ������� main �г���ȷ�� size������ʹ���ⲿ����� size��
    // ���ﷵ�� 0 ��ʾ���ɿ�������Ҫ file size�����ڵ���ʱ���룩��
    return 0;
}


// ������������ӡͳһ���ȷָ��� 
void PrintLine(const char* title)
{
    int totalLen = 50; // �̶��ܳ��� 
    if (!title) title = "";
    int titleLen = (int)strlen(title);
    int leftLen = (totalLen - titleLen - 2) / 2;
    int rightLen = totalLen - titleLen - 2 - leftLen; for (int i = 0; i < leftLen; i++) putchar('=');
    if (titleLen > 0) printf(" %s ", title);
    for (int i = 0;
        i < rightLen; i++) putchar('='); putchar('\n');
}

static const char* GetStringFromRva_Safe(PCHAR pFileBuffer, DWORD rva) {
    if (!pFileBuffer || rva == 0) return "<NULL>";
    DWORD foa = RvaToFoa(rva, pFileBuffer);
    if (!foa) return "<invalid_rva>";
    return (const char*)(pFileBuffer + foa);
}

// ---------- GetFileBuffer ----------
PCHAR GetFileBuffer(const char* filePath, DWORD* pFileSize) {
    if (!filePath) return NULL;
    FILE* f = fopen(filePath, "rb");
    if (!f) {
        printf("[-] ���ļ�ʧ��: %s\n", filePath);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    PCHAR buf = (PCHAR)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    size_t r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) {
        free(buf);
        printf("[-] �ļ���ȡ������\n");
        return NULL;
    }

    // ����֤ PE
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buf;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] ������Ч�� PE �ļ���DOS ħ������\n");
        free(buf);
        return NULL;
    }
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(buf + pDos->e_lfanew);
    if (pNts->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] ������Ч�� PE �ļ���NT ǩ������\n");
        free(buf);
        return NULL;
    }

    if (pFileSize) *pFileSize = (DWORD)sz;
    return buf;
}

// ---------- RvaToFoa ----------
DWORD RvaToFoa(DWORD Rva, PCHAR pFileBuffer) {
    if (!pFileBuffer) return 0;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);

    // ָ�뵽��һ����
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNts);
    // ͷ����Χ
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    if (Rva < pOpt->SizeOfHeaders) {
        // λ�� headers ����ֱ�ӷ��� Rva��FOA==RVA ���裩
        return Rva;
    }

    for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++) {
        DWORD va = pSec[i].VirtualAddress;
        DWORD vsize = pSec[i].Misc.VirtualSize;
        DWORD rawsize = pSec[i].SizeOfRawData;
        DWORD rawptr = pSec[i].PointerToRawData;

        DWORD secSize = vsize;
        if (secSize == 0 || secSize < rawsize) secSize = rawsize;

        if (Rva >= va && Rva < va + secSize) {
            return (Rva - va) + rawptr;
        }
    }
    // û�ҵ�
    return 0;
}

// ---------- Print: DOS ----------
VOID PrintfDos(PCHAR pFileBuffer) {
    if (!pFileBuffer) { printf("[-] NULL buffer\n"); return; }
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PrintLine("DOS_HEADER");
    printf("e_magic: 0x%04X ('%c%c')\n", pDos->e_magic,
        (char)(pDos->e_magic & 0xFF), (char)((pDos->e_magic >> 8) & 0xFF));
    printf("e_lfanew: 0x%08X\n", pDos->e_lfanew);
    PrintLine(NULL);
}

// ---------- Print: File Header ----------
VOID PrintfFileHeader(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER pFile = &pNts->FileHeader;

    PrintLine("FILE_HEADER");
    printf("Machine: 0x%04X\n", pFile->Machine);
    printf("NumberOfSections: %u\n", pFile->NumberOfSections);
    printf("SizeOfOptionalHeader: %u\n", pFile->SizeOfOptionalHeader);
    printf("Characteristics: 0x%04X\n", pFile->Characteristics);
    PrintLine(NULL);
}

// ---------- Print: Optional Header ----------
VOID PrintfOptional(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    PrintLine("OPTIONAL_HEADER");
    printf("Magic: 0x%04X\n", pOpt->Magic);
    printf("AddressOfEntryPoint: 0x%08X\n", pOpt->AddressOfEntryPoint);
    printf("ImageBase: 0x%08X\n", (unsigned int)pOpt->ImageBase);
    printf("SectionAlignment: 0x%08X\n", pOpt->SectionAlignment);
    printf("FileAlignment: 0x%08X\n", pOpt->FileAlignment);
    printf("SizeOfImage: 0x%08X\n", pOpt->SizeOfImage);
    PrintLine(NULL);
}

// ---------- Print: Section Table ----------
VOID PrintfSection(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNts);

    PrintLine("SECTION_TABLE");
    for (int i = 0; i < pNts->FileHeader.NumberOfSections; i++) {
        char name[9] = { 0 };
        memcpy(name, pSec[i].Name, 8);
        printf("[%02d] %s  VA:0x%08X  Raw:0x%08X  VSize:0x%08X  RawSize:0x%08X\n",
            i, name, pSec[i].VirtualAddress, pSec[i].PointerToRawData,
            pSec[i].Misc.VirtualSize, pSec[i].SizeOfRawData);
    }
    PrintLine(NULL);
}

// ---------- Print: Export Table (detail) ----------
VOID PrintfExport(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD expRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) { printf("[-] �޵�����\n"); return; }

    DWORD expFoa = RvaToFoa(expRva, pFileBuffer);
    if (!expFoa) { printf("[-] ������ FOA ��λʧ�ܡ�\n"); return; }
    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pFileBuffer + expFoa);

    const char* modName = GetStringFromRva_Safe(pFileBuffer, pExp->Name);
    PrintLine("EXPORT_TABLE");
    printf("Module: %s  Base: %u  #Funcs: %u  #Names: %u\n",
        modName, pExp->Base, pExp->NumberOfFunctions, pExp->NumberOfNames);

    DWORD addrOfNamesRva = pExp->AddressOfNames;
    DWORD addrOfNameOrdRva = pExp->AddressOfNameOrdinals;
    DWORD addrOfFuncsRva = pExp->AddressOfFunctions;

    DWORD namesFoa = addrOfNamesRva ? RvaToFoa(addrOfNamesRva, pFileBuffer) : 0;
    DWORD ordFoa = addrOfNameOrdRva ? RvaToFoa(addrOfNameOrdRva, pFileBuffer) : 0;
    DWORD funcFoa = addrOfFuncsRva ? RvaToFoa(addrOfFuncsRva, pFileBuffer) : 0;

    DWORD* nameArr = namesFoa ? (DWORD*)(pFileBuffer + namesFoa) : NULL;
    WORD* ordArr = ordFoa ? (WORD*)(pFileBuffer + ordFoa) : NULL;
    DWORD* funcArr = funcFoa ? (DWORD*)(pFileBuffer + funcFoa) : NULL;

    if (nameArr && ordArr && funcArr) {
        printf("[+] ���Ƶ����б�:\n");
        for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
            const char* fname = GetStringFromRva_Safe(pFileBuffer, nameArr[i]);
            WORD idx = ordArr[i];
            DWORD fRva = funcArr[idx];
            printf("  %04u: %-40s RVA:0x%08X\n", pExp->Base + idx, fname, fRva);
        }
    }
    else {
        printf("[-] δ�ܶ�λ��������������顣\n");
    }

    PrintLine(NULL);
}

// wrapper to keep original name in header
VOID PrintfExpOrt(PCHAR pFileBuffer) {
    PrintfExport(pFileBuffer);
}

// ---------- Print: Import Table (detail) ----------
VOID PrintfImport(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD impRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) { printf("[-] �޵����\n"); return; }

    DWORD impFoa = RvaToFoa(impRva, pFileBuffer);
    if (!impFoa) { printf("[-] ����� FOA ��λʧ�ܡ�\n"); return; }

    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuffer + impFoa);

    PrintLine("IMPORT_TABLE");
    while (pImp->Name) {
        const char* dllName = GetStringFromRva_Safe(pFileBuffer, pImp->Name);
        printf("[DLL] %s\n", dllName);

        // choose thunk
        DWORD thunkRva = pImp->OriginalFirstThunk ? pImp->OriginalFirstThunk : pImp->FirstThunk;
        if (!thunkRva) { printf("  [-] û�� thunk ��\n"); pImp++; continue; }

        DWORD thunkFoa = RvaToFoa(thunkRva, pFileBuffer);
        if (!thunkFoa) { printf("  [-] thunk FOA ��λʧ��\n"); pImp++; continue; }

        // �ж��� 32 ���� 64
        if (pNts->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            // 64-bit
            PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(pFileBuffer + thunkFoa);
            while (pThunk->u1.AddressOfData) {
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    DWORD ord = (DWORD)IMAGE_ORDINAL64(pThunk->u1.Ordinal);
                    printf("    [ORD] %u\n", ord);
                }
                else {
                    DWORD nameRva = (DWORD)pThunk->u1.AddressOfData;
                    PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pFileBuffer + RvaToFoa(nameRva, pFileBuffer));
                    printf("    %-40s (Hint:%u)\n", pIBN->Name, pIBN->Hint);
                }
                pThunk++;
            }
        }
        else {
            // 32-bit
            PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(pFileBuffer + thunkFoa);
            while (pThunk->u1.AddressOfData) {
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                    DWORD ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
                    printf("    [ORD] %u\n", ord);
                }
                else {
                    DWORD nameRva = (DWORD)pThunk->u1.AddressOfData;
                    PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pFileBuffer + RvaToFoa(nameRva, pFileBuffer));
                    printf("    %-40s (Hint:%u)\n", pIBN->Name, pIBN->Hint);
                }
                pThunk++;
            }
        }

        pImp++;
    }
    PrintLine(NULL);
}

// original name kept
VOID PrintfImportOld(PCHAR pFileBuffer) {
    PrintfImport(pFileBuffer);
}

// ---------- Print: Base Relocation ----------
VOID PrintfBase(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD baseRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (!baseRva) { printf("[-] ���ض�λ��\n"); return; }

    DWORD baseFoa = RvaToFoa(baseRva, pFileBuffer);
    if (!baseFoa) { printf("[-] �ض�λ�� FOA ��λʧ�ܡ�\n"); return; }

    PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)(pFileBuffer + baseFoa);
    PrintLine("BASE_RELOC");
    while (pRel->VirtualAddress && pRel->SizeOfBlock) {
        printf("Block VA: 0x%08X  Size: 0x%08X\n", pRel->VirtualAddress, pRel->SizeOfBlock);
        WORD* entries = (WORD*)((PCHAR)pRel + sizeof(IMAGE_BASE_RELOCATION));
        DWORD count = (pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (DWORD i = 0; i < count; i++) {
            WORD val = entries[i];
            WORD type = val >> 12;
            WORD offset = val & 0x0FFF;
            if (type != 0) {
                printf("  Type: %u  RVA: 0x%08X\n", type, pRel->VirtualAddress + offset);
            }
        }
        pRel = (PIMAGE_BASE_RELOCATION)((PCHAR)pRel + pRel->SizeOfBlock);
    }
    PrintLine(NULL);
}

// ---------- New: PrintImportDlls: list imported DLL names ----------
VOID PrintImportDlls(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD impRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) { printf("[-] �޵����\n"); return; }
    DWORD impFoa = RvaToFoa(impRva, pFileBuffer);
    if (!impFoa) { printf("[-] ����� FOA ��λʧ�ܡ�\n"); return; }

    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuffer + impFoa);
    int idx = 1;
    PrintLine("IMPORT DLLS");
    while (pImp->Name) {
        const char* dllName = GetStringFromRva_Safe(pFileBuffer, pImp->Name);
        printf("[%2d] %s\n", idx++, dllName);
        pImp++;
    }
    PrintLine(NULL);
}

// ---------- New: PrintExportDlls: list export module (usually current PE name) ----------
VOID PrintExportDlls(PCHAR pFileBuffer) {
    if (!pFileBuffer) return;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD expRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) { printf("[-] �޵�����\n"); return; }
    DWORD expFoa = RvaToFoa(expRva, pFileBuffer);
    if (!expFoa) { printf("[-] ������ FOA ��λʧ�ܡ�\n"); return; }

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pFileBuffer + expFoa);
    const char* modName = GetStringFromRva_Safe(pFileBuffer, pExp->Name);
    PrintLine("EXPORT MODULE");
    printf("  %s\n", modName);
    PrintLine(NULL);
}

// ---------- New: ShowDllFunctions: given dllName show either imports (for external dll) or exports (if matches own module) ----------
VOID ShowDllFunctions(PCHAR pFileBuffer, const char* dllName) {
    if (!pFileBuffer || !dllName || dllName[0] == 0) return;

    // normalize compare: case-insensitive
    // First check imports
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)(pFileBuffer + pDos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOpt = &pNts->OptionalHeader;

    DWORD impRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva) {
        DWORD impFoa = RvaToFoa(impRva, pFileBuffer);
        if (impFoa) {
            PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(pFileBuffer + impFoa);
            while (pImp->Name) {
                const char* name = GetStringFromRva_Safe(pFileBuffer, pImp->Name);
                if (_stricmp(name, dllName) == 0) {
                    PrintLine(name);
                    // list functions from this import descriptor
                    DWORD thunkRva = pImp->OriginalFirstThunk ? pImp->OriginalFirstThunk : pImp->FirstThunk;
                    if (!thunkRva) { printf("  [-] �� thunk\n"); return; }
                    DWORD thunkFoa = RvaToFoa(thunkRva, pFileBuffer);
                    if (!thunkFoa) { printf("  [-] thunk FOA ����\n"); return; }

                    if (pNts->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(pFileBuffer + thunkFoa);
                        while (pThunk->u1.AddressOfData) {
                            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                printf("    [ORD] %llu\n", (unsigned long long)IMAGE_ORDINAL64(pThunk->u1.Ordinal));
                            }
                            else {
                                DWORD nameRva = (DWORD)pThunk->u1.AddressOfData;
                                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pFileBuffer + RvaToFoa(nameRva, pFileBuffer));
                                printf("    %-40s (Hint:%u)\n", pIBN->Name, pIBN->Hint);
                            }
                            pThunk++;
                        }
                    }
                    else {
                        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(pFileBuffer + thunkFoa);
                        while (pThunk->u1.AddressOfData) {
                            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                                printf("    [ORD] %u\n", IMAGE_ORDINAL32(pThunk->u1.Ordinal));
                            }
                            else {
                                DWORD nameRva = (DWORD)pThunk->u1.AddressOfData;
                                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(pFileBuffer + RvaToFoa(nameRva, pFileBuffer));
                                printf("    %-40s (Hint:%u)\n", pIBN->Name, pIBN->Hint);
                            }
                            pThunk++;
                        }
                    }
                    PrintLine(NULL);
                    return;
                }
                pImp++;
            }
        }
    }

    // ���û�ڵ�������ҵ����ټ�鵼��ģ��������������
    DWORD expRva = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva) {
        DWORD expFoa = RvaToFoa(expRva, pFileBuffer);
        if (expFoa) {
            PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(pFileBuffer + expFoa);
            const char* myName = GetStringFromRva_Safe(pFileBuffer, pExp->Name);
            if (_stricmp(myName, dllName) == 0) {
                // list exports
                PrintLine(myName);
                DWORD namesFoa = pExp->AddressOfNames ? RvaToFoa(pExp->AddressOfNames, pFileBuffer) : 0;
                DWORD ordFoa = pExp->AddressOfNameOrdinals ? RvaToFoa(pExp->AddressOfNameOrdinals, pFileBuffer) : 0;
                DWORD funcFoa = pExp->AddressOfFunctions ? RvaToFoa(pExp->AddressOfFunctions, pFileBuffer) : 0;

                DWORD* nameArr = namesFoa ? (DWORD*)(pFileBuffer + namesFoa) : NULL;
                WORD* ordArr = ordFoa ? (WORD*)(pFileBuffer + ordFoa) : NULL;
                DWORD* funcArr = funcFoa ? (DWORD*)(pFileBuffer + funcFoa) : NULL;

                if (nameArr && ordArr && funcArr) {
                    for (DWORD i = 0; i < pExp->NumberOfNames; i++) {
                        const char* fname = GetStringFromRva_Safe(pFileBuffer, nameArr[i]);
                        WORD idx = ordArr[i];
                        DWORD fRva = funcArr[idx];
                        printf("  %04u: %-40s RVA:0x%08X\n", pExp->Base + idx, fname, fRva);
                    }
                }
                else {
                    // fallback: list all function RVAs
                    if (funcArr) {
                        for (DWORD i = 0; i < pExp->NumberOfFunctions; i++) {
                            printf("  %04u: RVA:0x%08X\n", pExp->Base + i, funcArr[i]);
                        }
                    }
                    else {
                        printf("  [-] �޵���������Ϣ\n");
                    }
                }
                PrintLine(NULL);
                return;
            }
        }
    }

    printf("[-] û���ҵ�ƥ��� DLL ����: %s\n", dllName);
}

// ---------- End of file ----------
