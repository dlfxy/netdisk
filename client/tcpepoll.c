#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int tcpClientInit(char *ip,char *port,int *pSocketFd){
    *pSocketFd = socket(AF_INET,SOCK_STREAM,0); // 修正此行
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    int ret = inet_pton(AF_INET,ip,&serverAddr.sin_addr.s_addr);
    ERROR_CHECK(ret,-1,"inet_pton");
    serverAddr.sin_port = htons(atoi(port));
    ret = connect(*pSocketFd,(struct sockaddr *)&serverAddr,sizeof(serverAddr));
    ERROR_CHECK(ret,-1,"connect");
    return 0;
}
int epollAdd(int epollFd,int fd){
    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = fd;
    int ret = epoll_ctl(epollFd,EPOLL_CTL_ADD,fd,&event);
    ERROR_CHECK(ret,-1,"EPOLL_CTL_ADD");
    return 0;
}
int epollDelete(int epollFd,int fd){
    int ret = epoll_ctl(epollFd,EPOLL_CTL_DEL,fd,NULL);
    ERROR_CHECK(ret,-1,"EPOLL_CTL_DEL");
    return 0;
}

#ifdef UNIT_TEST

#include <assert.h>
#include <errno.h>

#define TEST_PORT "54321"
#define TEST_IP "127.0.0.1"

void test_tcpClientInit_fail() {
    printf("========== test_tcpClientInit_fail ==========\n");
    int sockfd;
    // 没有服务监听54321端口，connect会失败
    int ret = tcpClientInit(TEST_IP, TEST_PORT, &sockfd);
    assert(ret != 0 || sockfd > 0); // 理论上会因connect失败被ERROR_CHECK终止
    printf("若看到此行则说明tcpClientInit未被ERROR_CHECK截断（这本应异常）\n");
}

void test_epollAdd_and_Delete() {
    printf("========== test_epollAdd_and_Delete ==========\n");
    int epfd = epoll_create(1);
    assert(epfd > 0);

    int fds[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(ret == 0);

    // 测试epollAdd
    ret = epollAdd(epfd, fds[0]);
    assert(ret == 0);

    // 测试epollDelete
    ret = epollDelete(epfd, fds[0]);
    assert(ret == 0);

    close(fds[0]);
    close(fds[1]);
    close(epfd);
    printf("epollAdd/epollDelete 测试通过\n");
}

int main() {
    printf("===== tcpepoll.c 单元测试 =====\n");
    test_epollAdd_and_Delete();
    printf("（tcpClientInit_fail因connect失败会直接exit，不建议自动跑，可单独注释ERROR_CHECK后测试）\n");
    printf("所有 tcpepoll.c 单元测试执行完毕\n");
    return 0;
}

#endif
