
int create_socket(char *ip, int port);
int sendline(int fd, char cont[], int size);
int sendlineafter(int fd, char *eof, char cont[], int len);
int recvuntil(int fd, char eof[]);

#define MAXSIZE 4096
#define true 1
#define false 0

char BUF[MAXSIZE];
char CONT[MAXSIZE];
// char IP[64];

typedef struct _Response {
  int size;
  char *buf;
} Response, *pResponse;


int menu();
int get_size(char *buf, int totalsize);
int create_socket(char *ip, int port);
int recvuntil(int fd, char *eof);
int recvline(int fd);
int sendline(int fd, char cont[], int size);
int sendlineafter(int fd, char *eof, char cont[], int len);