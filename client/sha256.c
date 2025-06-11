#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define READ_DATA_SIZE   1024
#define SHA256_SIZE      32
#define SHA256_STR_LEN   (SHA256_SIZE * 2)

/* SHA-256常量 */
static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* 内部辅助宏 */
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)     (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)    (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];

    /* 把输入数据整理成m[64] */
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for(i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void SHA256_Init(SHA256_CTX *ctx)
{
    ctx->bitcount = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void SHA256_Update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    size_t fill = ctx->bitcount / 8 % 64;
    size_t left = 64 - fill;
    ctx->bitcount += len * 8;

    if (fill && len >= left) {
        memcpy(ctx->buffer + fill, data, left);
        sha256_transform(ctx, ctx->buffer);
        data += left;
        len  -= left;
        fill = 0;
    }

    for (i = 0; i + 63 < len; i += 64)
        sha256_transform(ctx, data + i);

    if (len > i)
        memcpy(ctx->buffer + fill, data + i, len - i);
}

void SHA256_Final(SHA256_CTX *ctx, uint8_t hash[32])
{
    size_t fill = ctx->bitcount / 8 % 64;
    size_t i;
    uint8_t pad[64] = {0x80};

    uint64_t bits = ctx->bitcount;
    size_t padlen = (fill < 56) ? (56 - fill) : (120 - fill);

    SHA256_Update(ctx, pad, padlen);

    uint8_t lenbuf[8];
    for(i = 0; i < 8; i++)
        lenbuf[7 - i] = bits >> (i * 8);
    SHA256_Update(ctx, lenbuf, 8);

    for(i = 0; i < 8; i++) {
        hash[i*4+0] = (ctx->state[i] >> 24) & 0xff;
        hash[i*4+1] = (ctx->state[i] >> 16) & 0xff;
        hash[i*4+2] = (ctx->state[i] >> 8) & 0xff;
        hash[i*4+3] = (ctx->state[i] >> 0) & 0xff;
    }
}

/* 文件SHA256字符串输出 */
int Compute_file_sha256(const char *file_path, char *sha256_str)
{
    int fd;
    ssize_t ret;
    uint8_t data[READ_DATA_SIZE];
    uint8_t sha256_value[SHA256_SIZE];
    SHA256_CTX sha256;
    int i;

    fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    SHA256_Init(&sha256);

    while (1) {
        ret = read(fd, data, READ_DATA_SIZE);
        if (ret == -1) {
            perror("read");
            close(fd);
            return -1;
        }
        if (ret == 0)
            break;
        SHA256_Update(&sha256, data, ret);
    }

    close(fd);

    SHA256_Final(&sha256, sha256_value);

    for (i = 0; i < SHA256_SIZE; i++)
        snprintf(sha256_str + i*2, 3, "%02x", sha256_value[i]);
    sha256_str[SHA256_STR_LEN] = '\0';

    return 0;
}

/* 包装一层便于调用 */
int changeToSha256(const char *localPath, char *fileSha256)
{
    int ret;
    char sha256_str[SHA256_STR_LEN + 1];

    ret = Compute_file_sha256(localPath, sha256_str);
    if (ret == 0)
    {
        memcpy(fileSha256, sha256_str, strlen(sha256_str) + 1);
        printf("%s\n", sha256_str);
    }
    return 1;
}
/* 单元测试代码 */
#ifdef UNIT_TEST

#include <assert.h>
#include <stdlib.h>

/* 生成临时文件并写入内容 */
static void write_tmp_file(const char* filename, const char* content) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd > 0);
    write(fd, content, strlen(content));
    close(fd);
}

/* 测试 known value: "abc" 的SHA256 */
void test_sha256_abc() {
    const char* filename = "sha256_test_abc.txt";
    write_tmp_file(filename, "abc");
    char sha256[SHA256_STR_LEN + 1] = {0};
    int ret = Compute_file_sha256(filename, sha256);
    assert(ret == 0);
    // SHA256("abc") = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert(strcmp(sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    printf("[test_sha256_abc] PASS: %s\n", sha256);
    unlink(filename);
}

/* 测试 changeToSha256 的返回和内容 */
void test_changeToSha256() {
    const char* filename = "sha256_test_hello.txt";
    write_tmp_file(filename, "hello");
    char sha256[SHA256_STR_LEN + 1] = {0};
    int ret = changeToSha256(filename, sha256);
    // changeToSha256返回1
    assert(ret == 1);
    // SHA256("hello") = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert(strcmp(sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") == 0);
    printf("[test_changeToSha256] PASS: %s\n", sha256);
    unlink(filename);
}

/* 主测试入口 */
int main() {
    test_sha256_abc();
    test_changeToSha256();
    printf("All SHA256 unit tests passed!\n");
    return 0;
}

#endif
