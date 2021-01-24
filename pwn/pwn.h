
int create_socket(char *ip, int port);
int sendline(int fd, char cont[], int size);
int sendlineafter(int fd, char *eof, char cont[], int len);
int recvuntil(int fd, char eof[]);

#define MAXSIZE 4096

char BUF[MAXSIZE];
char CONT[MAXSIZE];
