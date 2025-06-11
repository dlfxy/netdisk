#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "sha256.h"
#define DIR_LABEL "DIR"
#define DIR_LABEL_WIDTH 8

// 打印左侧DIR栏和命令行提示
void print_cli_prompt(const char *user, const char *cwd) {
    // 清屏
    printf("\033[2J\033[H");
    // 左侧大写DIR
    printf("\033[1;34m%-*s\033[0m", DIR_LABEL_WIDTH, DIR_LABEL); // 蓝色高亮
    printf("  @%s: %s\n", user, cwd);
    printf("%-*s", DIR_LABEL_WIDTH, ""); // 补齐左栏
    fflush(stdout);
}

#ifndef UNIT_TEST

int main(int argc, char *argv[]) {
    ARGS_CHECK(argc, 3);
    char buf[1024] = {0};
    char cmd[128] = {0};
    char path1[128] = {0};
    char path2[128] = {0};
    char current_dir[512] = "~/"; // 默认初始目录
    char userName[128] = {0};

    // TCP 连接
    int socketFd;
    tcpClientInit(argv[1], argv[2], &socketFd);

    printf("===============================================\n");
    printf("|                  MYCLOUD                    |\n");
    printf("|                  v- 1.0                     |\n");
    printf("===============================================\n\n");

    // 登录/注册流程
    while (1) {
        char login_prompt[] = "Enter l to log in, enter s to sign up: ";
        write(STDOUT_FILENO, login_prompt, strlen(login_prompt));
        char word[32] = {0};
        scanf("%31s", word);

        if (strcmp(word, "l") != 0 && strcmp(word, "s") != 0) {
            continue;
        }

        user_t user;
        enterUser(&user);

        // 发送TLV类型命令
        tlv_t *type_tlv = (tlv_t *)malloc(sizeof(tlv_t) + 1);
        type_tlv->type = (strcmp(word, "l") == 0) ? AUTH_LOGIN : AUTH_REGISTER;
        type_tlv->len = 0;
        send(socketFd, type_tlv, sizeof(tlv_t), 0);
        free(type_tlv);

        // 发送用户信息
        tlv_t *user_tlv = (tlv_t *)malloc(sizeof(tlv_t) + sizeof(user_t));
        user_tlv->type = (strcmp(word, "l") == 0) ? AUTH_LOGIN : AUTH_REGISTER;
        user_tlv->len = sizeof(user_t);
        memcpy(user_tlv->value, &user, sizeof(user_t));
        send(socketFd, user_tlv, sizeof(tlv_t) + sizeof(user_t), 0);
        free(user_tlv);

        // 接收服务器响应
        char resp_buf[128] = {0};
        ssize_t ret = recvMessageFromServer(socketFd, resp_buf, sizeof(resp_buf));
        if (ret <= 0) {
            close(socketFd);
            return 0;
        }

        if (strcmp(word, "l") == 0) {
            // 登录
            if (strcmp(resp_buf, "0") == 0) {
                printf("%s: user does not exist\n\n", user.userName);
                continue;
            } else if (strcmp(resp_buf, "1") == 0) {
                printf("Welcome %s\n\n", user.userName);
                strcpy(userName, user.userName);
                break;
            } else if (strcmp(resp_buf, "2") == 0) {
                printf("Wrong password\n\n");
                continue;
            }
        } else {
            // 注册
            if (strcmp(resp_buf, "0") == 0) {
                printf("%s: username already exists\n\n", user.userName);
                continue;
            } else if (strcmp(resp_buf, "1") == 0) {
                printf("Sign up finished\n");
                strcpy(userName, user.userName);
                break;
            }
        }
    }

    // 获取初始目录
    memset(buf, 0, sizeof(buf));
    tlv_t *pwd_tlv = (tlv_t *)malloc(sizeof(tlv_t));
    pwd_tlv->type = CMD_PWD;
    pwd_tlv->len = 0;
    send(socketFd, pwd_tlv, sizeof(tlv_t), 0);
    free(pwd_tlv);
    ssize_t pwd_len = recvMessageFromServer(socketFd, buf, sizeof(buf));
    if (pwd_len > 0) {
        strncpy(current_dir, buf, sizeof(current_dir) - 1);
        current_dir[sizeof(current_dir) - 1] = '\0';
    }

    // epoll监听STDIN_FILENO和socketFd
    int epollFd = epoll_create(1);
    ERROR_CHECK(epollFd, -1, "epoll_create");
    epollAdd(epollFd, STDIN_FILENO);
    epollAdd(epollFd, socketFd);
    struct epoll_event eventArr[2];

    // 首次打印界面与提示
    print_cli_prompt(userName, current_dir);

    while (1) {
        int readyCount = epoll_wait(epollFd, eventArr, 2, -1);
        ERROR_CHECK(readyCount, -1, "epoll_wait");
        for (int i = 0; i < readyCount; ++i) {
            if (eventArr[i].data.fd == STDIN_FILENO) {
                memset(buf, 0, sizeof(buf));
                ssize_t stdinLength = recvStdin(buf, sizeof(buf));
                if (!stdinLength) {
                    close(epollFd);
                    close(socketFd);
                    return 0;
                }

                // 解析命令
                memset(cmd, 0, sizeof(cmd));
                memset(path1, 0, sizeof(path1));
                memset(path2, 0, sizeof(path2));
                int cutRet = cutCmd(buf, cmd, path1, path2);
                if (!checkArguments(cmd, path1, path2, cutRet)) {
                    print_cli_prompt(userName, current_dir);
                    continue;
                }

                // 命令处理
                if (strcmp(cmd, "puts") == 0) {
                    char sha256[128] = {0};
                    changeToSha256(path1, sha256);

                    tlv_t *puts_tlv = (tlv_t *)malloc(sizeof(tlv_t) + strlen(path2) + 1);
                    puts_tlv->type = CMD_UPLOAD;
                    puts_tlv->len = strlen(path2) + 1;
                    memcpy(puts_tlv->value, path2, puts_tlv->len);
                    send(socketFd, puts_tlv, sizeof(tlv_t) + puts_tlv->len, 0);
                    free(puts_tlv);

                    tlv_t *sha_tlv = (tlv_t *)malloc(sizeof(tlv_t) + strlen(sha256) + 1);
                    sha_tlv->type = TRANS_META;
                    sha_tlv->len = strlen(sha256) + 1;
                    memcpy(sha_tlv->value, sha256, sha_tlv->len);
                    send(socketFd, sha_tlv, sizeof(tlv_t) + sha_tlv->len, 0);
                    free(sha_tlv);

                    char sec_buf[8] = {0};
                    recvMessageFromServer(socketFd, sec_buf, sizeof(sec_buf));
                    if (strcmp(sec_buf, "1") == 0) {
                        printf("putting......\nputs finished (秒传)\n");
                        print_cli_prompt(userName, current_dir);
                        continue;
                    } else if (strcmp(sec_buf, "0") == 0) {
                        sendFileToServer(socketFd, path1, path2);
                        printf("putting......\nputs finished\n");
                        print_cli_prompt(userName, current_dir);
                        continue;
                    } else if (strcmp(sec_buf, "2") == 0) {
                        printf("puts: %s: No such file or directory\n", path2);
                        print_cli_prompt(userName, current_dir);
                        continue;
                    }
                } else if (strcmp(cmd, "gets") == 0) {
                    tlv_t *gets_tlv = (tlv_t *)malloc(sizeof(tlv_t) + strlen(path1) + 1);
                    gets_tlv->type = CMD_DOWNLOAD;
                    gets_tlv->len = strlen(path1) + 1;
                    memcpy(gets_tlv->value, path1, gets_tlv->len);
                    send(socketFd, gets_tlv, sizeof(tlv_t) + gets_tlv->len, 0);
                    free(gets_tlv);

                    char exist_buf[8] = {0};
                    recvMessageFromServer(socketFd, exist_buf, sizeof(exist_buf));
                    if (strcmp(exist_buf, "0") == 0) {
                        printf("gets: %s: No such file or directory\n", path1);
                        print_cli_prompt(userName, current_dir);
                        continue;
                    }
                } else if (strcmp(cmd, "cd") == 0) {
                    // 目录切换命令
                    tlv_t *cd_tlv = (tlv_t *)malloc(sizeof(tlv_t) + strlen(path1) + 1);
                    cd_tlv->type = CMD_LONG_CD;
                    cd_tlv->len = strlen(path1) + 1;
                    memcpy(cd_tlv->value, path1, cd_tlv->len);
                    send(socketFd, cd_tlv, sizeof(tlv_t) + cd_tlv->len, 0);
                    free(cd_tlv);
                } else {
                    // 其它命令
                    tlv_t *msg_tlv = (tlv_t *)malloc(sizeof(tlv_t) + strlen(buf) + 1);
                    msg_tlv->type = CMD_SHORT_LS;
                    msg_tlv->len = strlen(buf) + 1;
                    memcpy(msg_tlv->value, buf, msg_tlv->len);
                    send(socketFd, msg_tlv, sizeof(tlv_t) + msg_tlv->len, 0);
                    free(msg_tlv);
                }

            } else {
                // 接收服务器消息
                ssize_t recvRet = recvMessageFromServer(socketFd, buf, sizeof(buf));
                if (!recvRet) {
                    close(epollFd);
                    close(socketFd);
                    return 0;
                }
                // 检查是否是目录变更回包
                if (strncmp(buf, "CDOK:", 5) == 0) {
                    // 目录切换成功，更新当前目录
                    strncpy(current_dir, buf + 5, sizeof(current_dir) - 1);
                    current_dir[sizeof(current_dir) - 1] = '\0';
                    print_cli_prompt(userName, current_dir);
                    continue;
                }
                printf("%s\n", buf);

                // 下载命令
                if (strncmp(buf, "ready_to_download", 17) == 0) {
                    recvFileFromServer(socketFd);
                    printf("gets finished\n");
                }
                print_cli_prompt(userName, current_dir);
            }
        }
    }
    return 0;
}
#else

// ========= 单元测试部分 =========

void test_print_cli_prompt() {
    printf("========== test_print_cli_prompt ==========\n");
    const char *user = "testuser";
    const char *cwd = "/home/testuser/projects";
    print_cli_prompt(user, cwd);
    printf("请确认左侧有蓝色高亮DIR，右侧为@用户名: 目录路径\n");
    printf("========== END test_print_cli_prompt ==========\n\n");
}

void test_cd_update() {
    printf("========== test_cd_update ==========\n");
    char user[] = "dlfxy";
    char cwd[128] = "/home/dlfxy";
    print_cli_prompt(user, cwd);
    printf("当前目录: %s\n", cwd);

    // 模拟切换目录
    strcpy(cwd, "/home/dlfxy/dir1");
    print_cli_prompt(user, cwd);
    printf("切换后目录: %s\n", cwd);

    strcpy(cwd, "/tmp");
    print_cli_prompt(user, cwd);
    printf("再次切换目录: %s\n", cwd);
    printf("========== END test_cd_update ==========\n\n");
}

void test_command_input() {
    printf("========== test_command_input ==========\n");
    char user[] = "testuser";
    char cwd[128] = "/home/testuser";
    print_cli_prompt(user, cwd);

    // 模拟用户输入
    printf("模拟输入命令: puts a.txt /cloud/a.txt\n");
    char cmd[128], path1[128], path2[128];
    char buf[] = "puts a.txt /cloud/a.txt";
    int ret = cutCmd(buf, cmd, path1, path2);
    printf("解析结果: cmd=%s, path1=%s, path2=%s, ret=%d\n", cmd, path1, path2, ret);

    print_cli_prompt(user, cwd);
    printf("模拟输入命令: cd /home/testuser/project\n");
    strcpy(buf, "cd /home/testuser/project");
    ret = cutCmd(buf, cmd, path1, path2);
    printf("解析结果: cmd=%s, path1=%s, path2=%s, ret=%d\n", cmd, path1, path2, ret);

    printf("========== END test_command_input ==========\n\n");
}

int main() {
    test_print_cli_prompt();
    sleep(1); // 便于观察界面
    test_cd_update();
    sleep(1); // 便于观察界面
    test_command_input();
    printf("所有单元测试执行完毕。\n");
    return 0;
}

#endif
