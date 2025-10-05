#include "PE_Config.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

void print_logo() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, 10);

    const char* banner[] = {
        "",
        "██████╗ ███████╗███╗   ███╗ █████╗ ██████╗",
        "██╔══██╗██╔════╝████╗ ████║██╔══██╗██╔══██╗",
        "██████╔╝█████╗  ██╔████╔██║███████║██████╔╝",
        "██╔═══╝ ██╔══╝  ██║╚██╔╝██║██╔══██║██╔═══╝",
        "██║     ███████╗██║ ╚═╝ ██║██║  ██║██║",
        "╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝",
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

// CLI 循环
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

        // 退出
        if (strcmp(cmd, "exit") == 0) break;

        // 清屏
        else if (strcmp(cmd, "cls") == 0) {
            system("cls");
            print_logo();
            continue;
        }

        // 帮助
        else if (strcmp(cmd, "help") == 0) {
            PrintLine(NULL);
            printf("命令列表:\n");
            printf("  open <path>    打开 PE 文件\n");
            printf("  dos            查看 DOS 头\n");
            printf("  file           查看文件头\n");
            printf("  opt            查看可选头\n");
            printf("  sec            查看节区表\n");
            printf("  imp            查看导入 DLL\n");
            printf("  imp <dll>      查看指定 DLL 的导入函数\n");
            printf("  exp            查看导出函数\n");
            printf("  base           查看镜像基址\n");
            printf("  cls            清屏\n");
            printf("  help           显示此帮助\n");
            printf("  exit           退出程序\n");
            PrintLine(NULL);
            continue;
        }

        // 打开文件
        else if (strncmp(cmd, "open ", 5) == 0) {
            char* path = cmd + 5;
            if (*pFileBuffer) {
                free(*pFileBuffer);
                *pFileBuffer = NULL;
            }
            DWORD fsize = 0;
            *pFileBuffer = GetFileBuffer(path, &fsize);
            if (*pFileBuffer) {
                printf("已打开文件: %s (%lu bytes)\n", path, fsize);
            }
            else {
                printf("打开文件失败: %s\n", path);
            }
            continue;
        }

        // 检查是否已经打开文件
        if (!*pFileBuffer) {
            printf("请先使用 open <path> 打开 PE 文件\n");
            continue;
        }

        // 各功能命令
        if (strcmp(cmd, "dos") == 0) PrintfDos(*pFileBuffer);
        else if (strcmp(cmd, "file") == 0) PrintfFileHeader(*pFileBuffer);
        else if (strcmp(cmd, "opt") == 0) PrintfOptional(*pFileBuffer);
        else if (strcmp(cmd, "sec") == 0) PrintfSection(*pFileBuffer);
        else if (strcmp(cmd, "base") == 0) PrintfBase(*pFileBuffer);
        else if (strcmp(cmd, "imp") == 0) PrintImportDlls(*pFileBuffer);
        else if (strncmp(cmd, "imp ", 4) == 0) ShowDllFunctions(*pFileBuffer, cmd + 4);
        else if (strcmp(cmd, "exp") == 0) PrintExportDlls(*pFileBuffer);
        else printf("未知命令: %s (输入 'help' 查看帮助)\n", cmd);
    }
}

int main(int argc, char* argv[]) {
    print_logo();

    PCHAR fileBuffer = NULL;

    if (argc >= 2) {
        DWORD fsize = 0;
        fileBuffer = GetFileBuffer(argv[1], &fsize);
        if (!fileBuffer) {
            printf("打开文件失败: %s\n", argv[1]);
        }
        else {
            printf("已打开文件: %s (%lu bytes)\n", argv[1], fsize);
        }
    }

    cli_loop(&fileBuffer);

    if (fileBuffer) free(fileBuffer);
    printf("程序退出\n");
    return 0;
}
