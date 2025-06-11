#include"client.h"
// 假设已存在的用户名列表（实际应从数据库/文件读取）
const char *existing_users[] = {"admin", "root", "test_user", "guest"};
const int existing_user_count = 4;

// 判断用户名是否已存在
int isUserNameExist(const char *name) {
    for (int i = 0; i < existing_user_count; ++i) {
        if (strcmp(name, existing_users[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// 被测函数：注册
int registerUser(user_t *user) {
    memset(user, 0, sizeof(user_t));
    char pswd1[1024] = {0};
    char pswd2[1024] = {0};

    // 1. 输入用户名，判断是否重名
    while (1) {
        printf("Enter username: ");
        fflush(stdout);
        if(scanf("%127s", user->userName) != 1) {
            fprintf(stderr, "Failed to read username.\n");
            return -1;
        }
        // 清理输入缓冲区
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        if (isUserNameExist(user->userName)) {
            printf("Username already exists, please try again.\n");
            memset(user->userName, 0, sizeof(user->userName));
        } else {
            break;
        }
    }

    // 2. 输入两次密码并判断
    char *p1 = getpass("Enter password: ");
    if (!p1) {
        fprintf(stderr, "Failed to read password.\n");
        return -1;
    }
    strncpy(pswd1, p1, sizeof(pswd1) - 1);

    char *p2 = getpass("Re-enter password: ");
    if (!p2) {
        fprintf(stderr, "Failed to read password.\n");
        return -1;
    }
    strncpy(pswd2, p2, sizeof(pswd2) - 1);

    if (strcmp(pswd1, pswd2) == 0) {
        strncpy(user->passwd, pswd1, sizeof(user->passwd) - 1);
        user->passwd[sizeof(user->passwd) - 1] = '\0';
        printf("Register success!\n");
        return 0;
    } else {
        printf("Register failed: passwords do not match!\n");
        return -1;
    }
}

#ifdef UNIT_TEST

// 测试专用假getpass
char *fake_getpass(const char *prompt) {
    static char buf[2][128] = {"test_password", "test_password"};
    static int call = 0;
    printf("%s", prompt);
    return buf[call++];
}

// 单元测试主函数
int main() {
    user_t user;
    // 输入流内容：重名 admin 回车 -> 不重名 new_user 回车
    const char *input_text = "admin\nnew_user\n";
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

    int ret = registerUser(&user);

    // 恢复stdin
    dup2(old_stdin, STDIN_FILENO);
    close(old_stdin);
    fclose(input);

    // 检查结果
    if(ret == 0 &&
       strcmp(user.userName, "new_user") == 0 &&
       strcmp(user.passwd, "test_password") == 0) {
        printf("Register unit test passed!\n");
        return 0;
    } else {
        printf("Register unit test failed!\n");
        printf("userName: %s\n", user.userName);
        printf("passwd: %s\n", user.passwd);
        return 1;
    }
}
#endif
