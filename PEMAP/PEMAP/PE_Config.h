#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

#pragma warning(disable:4996) // 关闭 fopen 安全警告

// ------------------ 工具函数 ------------------
PCHAR GetFileBuffer(const char* filePath, DWORD* fileSize);
DWORD RvaToFoa(DWORD Rva, PCHAR pFileBuffer);

// ------------------ 打印函数 ------------------
VOID PrintfDos(PCHAR pFileBuffer);
VOID PrintfFileHeader(PCHAR pFileBuffer);
VOID PrintfOptional(PCHAR pFileBuffer);
VOID PrintfSection(PCHAR pFileBuffer);
VOID PrintfImport(PCHAR pFileBuffer);
VOID PrintfExport(PCHAR pFileBuffer);
VOID PrintfBase(PCHAR pFileBuffer);

// ------------------ 新功能函数 ------------------
VOID PrintImportDlls(PCHAR pFileBuffer);
VOID PrintExportDlls(PCHAR pFileBuffer);
VOID ShowDllFunctions(PCHAR pFileBuffer, const char* dllName);

VOID print_logo();
VOID cli_loop(PCHAR pFileBuffer);







