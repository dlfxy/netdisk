#ifndef CLIENT_H
#define CLIENT_H

#include <my_header.h>
#include <stdint.h>  // 为了使用uint8_t, uint16_t等类型

// TLV协议类型枚举
typedef enum{
    //  命令类型:COMMAND,0*
    CMD_SHORT_CD,   // 短的cd,不带数据
    CMD_SHORT_LS,   // 短的ls，不带数据
    CMD_LONG_CD,    // 长的cd，携带路径
    CMD_MKDIR,      // 创建目录
    CMD_PWD,        // 查看当前目录
    CMD_RM,         // 删除文件
    CMD_UPLOAD,     // 上传
    CMD_DOWNLOAD,   // 下载

    // 认证类型:AUTH,1*
    AUTH_REGISTER = 16,// 用户注册
    AUTH_LOGIN,     // 用户登录
    AUTH_LOGOUT,    // 用户登出
    AUTH_TOK,       // 发送token
    AUTH_TOK_REF,   // Token刷新

    // 文件传输类型:TRANS,2*
    TRANS_META = 32,// 文件元数据
    TRANS_CHUNK_DATA,// 文件分块数据
    END_MARKER,     // 传输结束标志，空包
    TRANS_RESEND,   // 重传请求
    TRANS_STREAM_BEG,// 流式传输开始，空包
    STREAM_END,     // 流式传输结束，空包

    // 相应类型:RESPONSE暂时保留,3*
    DATA_RESPONSE = 48,// 数据响应
    STATUS,         // 状态更新

    // 错误类型:ERROR,4*
    ERR_AUTH_NAME_CONFLICT = 64,// 重名错误
    ERR_AUTH_PASSWORD_INVALID,  // 密码错误
    ERR_AUTH_USER_NOT_FOUND,    // 未找到用户名
    ERR_FILE,                   // 文件操作错误
    ERR_NET,                    // 网络错误
    ERR_SER                     // 服务端内部错误
} tlvType;

// TLV协议结构体，用于网络消息传输
typedef struct tlv_s{
    uint8_t type;      // 类型(1字节)
    uint16_t len;      // 数据长度(2字节)
    uint8_t value[];   // 柔性数组，实际数据
} tlv_t;


// 用户信息结构体
typedef struct user_s {
    char userName[128];
    char passwd[1024];
} user_t;


/* trainsmission.c */
int sendMessageToServer(int fd, char *buf, int sendLength);       // 发消息
int sendFileToServer(int fd, char *localPath, char *virtualPath); // 发文件
int changeToSha256(char *localPath, char *fileSha256);            // 计算文件sha-256   
ssize_t recvStdin(char *buf, int bufLength);                      // 收标准输入
ssize_t recvMessageFromServer(int fd, char *buf, int bufLength);  // 收消息
int recvFileFromServer(int fd);                                   // 收文件

/* tcpepoll.c */
int tcpClientInit(char *ip, char *port, int *pSocketFd); // TCP 连接
int epollAdd(int epfd, int fd);                          // 添加监听
int epollDelete(int epfd, int fd);                       // 删除监听

/* login.h */
int enterUser(user_t *user);

/* command.c */
int cutCmd(char *input,char *cmd,char *path1,char *path2);
int checkCmd(const char *cmd);
int checkArguments(const char *cmd, const char *path1, const char *path2, int cutRet);
int cutTail(char *path, char *left, char *right);

#endif // CLIENT_H
