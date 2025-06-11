#ifndef SHA256_H
#define SHA256_H

#include <my_header.h>
#include <stdint.h>

// SHA-256上下文结构体
typedef struct
{
    uint32_t state[8];     // 保存中间哈希值
    uint64_t bitcount;     // 消息长度（比特数）
    uint8_t buffer[64];    // 数据块缓冲区
} SHA256_CTX;

// SHA-256主函数接口
void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void SHA256_Final(SHA256_CTX *ctx, uint8_t hash[32]);

// 文件SHA-256摘要计算
int changeToSha256(char *localPath, char *fileSha256);
int Compute_file_sha256(const char *file_path, char *value);

#endif // SHA256_H
