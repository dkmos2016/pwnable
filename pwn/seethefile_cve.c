

#include <stdio.h>
#include "pwn.h"


int login(int fd, char *cont, int size) {
    sendlineafter(fd, ">> ", "1", 1);
    sendlineafter(fd, "Your passowrd :", cont, size);
    int sz = recvline(fd);

    return strstr(BUF, "Failed")? false: true;
}

int main() {
    int fd = create_socket("127.0.0.1", 9999);

    if (fd == -1) {
        return -1;
    }

    login(fd, "hello", 5);
    return 0;
}
