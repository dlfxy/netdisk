#include "client.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  // for crypt, dup, etc.
#include <crypt.h>   // for crypt

// 假设已经注册的用户信息（实际应从服务器/数据库获取）
typedef struct {
    char userName[128];
    char salt[32];
    char passwd_hash[128];
} user_db_entry;

// 举例：已有用户test_user，密码test_password，盐"$6$testsalt$"
const user_db_entry registered_users[] = {
    // crypt("test_password", "$6$testsalt$")
    {"test_user", "$6$testsalt$", "$6$testsalt$WnYv7UG1eJUyP9xMIf.jTJGYtAdM6eG0L1WUqRJzKLu5jxknjyjGLdOQKdXX42a35xuobwkAFFha3tF3wZ9us1"},
    // 你可以再增加其他用户
};
const int registered_user_count = sizeof(registered_users)/sizeof(registered_users[0]);

// 查找用户名，返回对应的user_db_entry指针，找不到返回NULL
const user_db_entry *find_user(const char *username) {
    for(int i=0; i<registered_user_count; ++i) {
        if(strcmp(registered_users[i].userName, username) == 0)
            return &registered_users[i];
    }
    return NULL;
}

// 被测函数：登录
int enterUser(user_t *user) {
    memset(user, 0, sizeof(user_t));

    // 输入用户名
    printf("Enter username: ");
    fflush(stdout);
    if(scanf("%127s", user->userName) != 1) {
        fprintf(stderr, "Failed to read username.\n");
        return -1;
    }
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    // ==============================
    // 这里本应从服务器获取盐值: 
    // char salt[32];
    // recv(fd, salt, ...);
    // 现简化为本地查找
    const user_db_entry *db_user = find_user(user->userName);
    if (!db_user) {
        printf("User not found.\n");
        return -2;
    }
    char salt[32] = {0};
    strncpy(salt, db_user->salt, sizeof(salt)-1);
    // ==============================

    // 输入密码（隐藏回显）
    char *realPasswd = getpass("Enter password: ");
    if (realPasswd == NULL) {
        fprintf(stderr, "Failed to read password.\n");
        return -1;
    }

    // 本应客户端用crypt加密后再发给服务器，现直接本地对比hash
    char *hashed = crypt(realPasswd, salt);
    if (!hashed) {
        fprintf(stderr, "crypt error.\n");
        return -1;
    }

    // ==============================
    // 这里本应发送密文到服务器，服务器比对
    // send(fd, hashed, ...);
    // 现直接本地比对
    if (strcmp(hashed, db_user->passwd_hash) == 0) {
        // 登录成功
        strncpy(user->passwd, realPasswd, sizeof(user->passwd)-1);
        user->passwd[sizeof(user->passwd)-1] = '\0';
        printf("Login success!\n");
        return 0;
    } else {
        printf("Login failed: password incorrect!\n");
        return -1;
    }
    // ==============================
}

#ifdef UNIT_TEST
// ===== 单元测试部分 =====

// 测试专用假getpass
char *fake_getpass(const char *prompt) {
    static char password[128] = "test_password";
    printf("%s", prompt);
    return password;
}

int main() {
    user_t user;
    // 输入流内容：test_user 回车
    const char *input_text = "test_user\n";
    FILE *input = fmemopen((void*)input_text, strlen(input_text), "r");
    if (!input) {
        perror("fmemopen");
        return 1;
    }
    int old_stdin = dup(STDIN_FILENO);
    dup2(fileno(input), STDIN_FILENO);

    // 宏替换getpass为fake_getpass
    #undef getpass
    #define getpass fake_getpass

    int ret = enterUser(&user);

    // 恢复stdin
    dup2(old_stdin, STDIN_FILENO);
    close(old_stdin);
    fclose(input);

    // 检查结果
    if(ret == 0 &&
       strcmp(user.userName, "test_user") == 0 &&
       strcmp(user.passwd, "test_password") == 0) {
        printf("Login unit test passed!\n");
        return 0;
    } else {
        printf("Login unit test failed!\n");
        printf("userName: %s\n", user.userName);
        printf("passwd: %s\n", user.passwd);
        return 1;
    }
}
#endif
