#include "PE_Config.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

void print_logo() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 10);

    const char* banner[] = {
        "",
        "�������������[ ���������������[�������[   �������[ �����������[ �������������[",
        "�����X�T�T�����[�����X�T�T�T�T�a���������[ ���������U�����X�T�T�����[�����X�T�T�����[",
        "�������������X�a�����������[  �����X���������X�����U���������������U�������������X�a",
        "�����X�T�T�T�a �����X�T�T�a  �����U�^�����X�a�����U�����X�T�T�����U�����X�T�T�T�a",
        "�����U     ���������������[�����U �^�T�a �����U�����U  �����U�����U",
        "�^�T�a     �^�T�T�T�T�T�T�a�^�T�a     �^�T�a�^�T�a  �^�T�a�^�T�a",
        "",
        "           PE Structure Analysis Tool v1.0",
        NULL
    };

    for (int i = 0; banner[i] != NULL; i++) {
        printf("%s\n", banner[i]);
        Sleep(30);
    }
    SetConsoleTextAttribute(hConsole, 7);
    printf("\nType 'help' for command list.\n");
}

// CLI ѭ��
void cli_loop(PCHAR* pFileBuffer) {
    char cmd[256];

    while (1) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, 10);
        printf("PEtool > ");
        SetConsoleTextAttribute(hConsole, 7);

        fgets(cmd, sizeof(cmd), stdin);
        cmd[strcspn(cmd, "\n")] = 0;

        if (strlen(cmd) == 0) continue;

        // �˳�
        if (strcmp(cmd, "exit") == 0) break;

        // ����
        else if (strcmp(cmd, "cls") == 0) {
            system("cls");
            print_logo();
            continue;
        }

        // ����
        else if (strcmp(cmd, "help") == 0) {
            PrintLine(NULL);
            printf("�����б�:\n");
            printf("  open <path>    �� PE �ļ�\n");
            printf("  dos            �鿴 DOS ͷ\n");
            printf("  file           �鿴�ļ�ͷ\n");
            printf("  opt            �鿴��ѡͷ\n");
            printf("  sec            �鿴������\n");
            printf("  imp            �鿴���� DLL\n");
            printf("  imp <dll>      �鿴ָ�� DLL �ĵ��뺯��\n");
            printf("  exp            �鿴��������\n");
            printf("  base           �鿴�����ַ\n");
            printf("  cls            ����\n");
            printf("  help           ��ʾ�˰���\n");
            printf("  exit           �˳�����\n");
            PrintLine(NULL);
            continue;
        }

        // ���ļ�
        else if (strncmp(cmd, "open ", 5) == 0) {
            char* path = cmd + 5;
            if (*pFileBuffer) {
                free(*pFileBuffer);
                *pFileBuffer = NULL;
            }
            DWORD fsize = 0;
            *pFileBuffer = GetFileBuffer(path, &fsize);
            if (*pFileBuffer) {
                printf("�Ѵ��ļ�: %s (%lu bytes)\n", path, fsize);
            }
            else {
                printf("���ļ�ʧ��: %s\n", path);
            }
            continue;
        }

        // ����Ƿ��Ѿ����ļ�
        if (!*pFileBuffer) {
            printf("����ʹ�� open <path> �� PE �ļ�\n");
            continue;
        }

        // ����������
        if (strcmp(cmd, "dos") == 0) PrintfDos(*pFileBuffer);
        else if (strcmp(cmd, "file") == 0) PrintfFileHeader(*pFileBuffer);
        else if (strcmp(cmd, "opt") == 0) PrintfOptional(*pFileBuffer);
        else if (strcmp(cmd, "sec") == 0) PrintfSection(*pFileBuffer);
        else if (strcmp(cmd, "base") == 0) PrintfBase(*pFileBuffer);
        else if (strcmp(cmd, "imp") == 0) PrintImportDlls(*pFileBuffer);
        else if (strncmp(cmd, "imp ", 4) == 0) ShowDllFunctions(*pFileBuffer, cmd + 4);
        else if (strcmp(cmd, "exp") == 0) PrintExportDlls(*pFileBuffer);
        else printf("δ֪����: %s (���� 'help' �鿴����)\n", cmd);
    }
}

int main(int argc, char* argv[]) {
    print_logo();

    PCHAR fileBuffer = NULL;

    if (argc >= 2) {
        DWORD fsize = 0;
        fileBuffer = GetFileBuffer(argv[1], &fsize);
        if (!fileBuffer) {
            printf("���ļ�ʧ��: %s\n", argv[1]);
        }
        else {
            printf("�Ѵ��ļ�: %s (%lu bytes)\n", argv[1], fsize);
        }
    }

    cli_loop(&fileBuffer);

    if (fileBuffer) free(fileBuffer);
    printf("�����˳�\n");
    return 0;
}
