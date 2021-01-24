

#include <stdio.h>
#include <sys/types.h> /* See NOTES */
#include <sys/socket.h>
#include <netdb.h>

#include "pwn.h"

#define PORT 10200
#define HOST "chall.pwnable.tw"
#define IP "139.162.123.119"

int menu()
{
    return 0;
}

int create_socket(char *ip, int port)
{
    int sock_fd;
    struct sockaddr_in serv_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("create socket failed\n");
        return -1;
    }

    bzero(&serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    // inet_pton(AF_INET, HOST, (void *)&serv_addr.sin_addr);
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    int ret = connect(sock_fd, &serv_addr, sizeof(serv_addr));
    if (ret == -1)
    {
        printf("connot connect %s!\n", ip);
        return -1;
    }

    return sock_fd;
}

int recvuntil(int fd, char *eof)
{
    int i = 0;
    char tmp;
    bzero(BUF, MAXSIZE);
    for (i = 0; i < MAXSIZE; i++)
    {
        recv(fd, BUF + i, 1, 0);
        if (strstr(BUF, eof))
        {
            break;
        }
    }
    return i;
}

int sendline(int fd, char cont[], int size)
{
    int i;
    int flag = 0;

    for (i = 0; i < size; i++)
    {
        write(fd, cont + i, 1);
        if (cont[i] == '\x0a')
        {
            flag = 1;
            break;
        }
    }

    if (!flag)
    {
        write(fd, "\x0a", 1);
        i++;
    }

    return i;
}

int sendlineafter(int fd, char *eof, char cont[], int len)
{
    int ret = recvuntil(fd, eof);
    if (!ret)
        return -1;

    ret = sendline(fd, cont, len);

    printf("sended %d bytes\n", ret);
    return 0;
}

int mainlib(int argc, char *argv[])
{
    int sock_fd, recvbytes;
    struct hostent *host;
    struct sockaddr_in serv_addr;

    sock_fd = create_socket(IP, PORT);
    if (sock_fd == -1)
    {
        printf("cannot create socket!\n");
        return -1;
    }

    sendlineafter(sock_fd, "Your choice :", "1", 1);
    sendlineafter(sock_fd, "What do you want to see :", "/etc/passwd", strlen("/etc/passwd"));

    // sendlineafter(sock_fd, "Your choice :", "2");
    // sendlineafter(sock_fd, "Your choice :", "3");

    // recvuntil(sock_fd, "Your choice :");
    // sendline(sock_fd, "2");
    // sendline(sock_fd, "3");
    recvuntil(sock_fd, "Your choice :");

    printf("%s\n", BUF);

    close(sock_fd);

    return 0;
}