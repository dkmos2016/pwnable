

#include <stdio.h>

void openfile(char *fname);
void read();
void output();
void close();
void exit();
void payload(char cont[], int count);

typedef struct _VTABLE_JUMP
{
    __uint32_t __dummy;
    __uint32_t __dummy2;
    __uint32_t __finish;
    __uint32_t __overflow;
    __uint32_t __underflow;
    __uint32_t __uflow;
    __uint32_t __pbackfail;
    __uint32_t __xsputn;
    __uint32_t __xsgetn;
    __uint32_t __seekoff;
    __uint32_t __seekpos;
    __uint32_t __setbuf;
    __uint32_t __sync;
    __uint32_t __doallocate;
    __uint32_t __read;
    __uint32_t __write;
    __uint32_t __seek;
    __uint32_t __stat;
    __uint32_t __showmanyc;
    __uint32_t __imbue;
} VTABLE_JUMP;

typedef struct _FILE
{
    __uint32_t _flags;
    __uint32_t _IO_read_ptr;
    __uint32_t _IO_read_end;
    __uint32_t _IO_read_base;
    __uint32_t _IO_write_base;
    __uint32_t _IO_write_ptr;
    __uint32_t _IO_write_end;
    __uint32_t _IO_buf_base;
    __uint32_t _IO_buf_end;
    __uint32_t _IO_save_base;
    __uint32_t _IO_backup_base;
    __uint32_t _IO_save_end;
    __uint32_t _markers;
    __uint32_t _chain;
    __uint32_t _fileno;
    __uint32_t _flags2;
    __uint32_t _old_offset;
    __uint16_t _cur_column;
    __uint8_t _vtable_offset;
    __uint8_t _shortbuf;
    __uint32_t _lock;
    __uint64_t _offset;
    __uint32_t _codecvt;
    __uint32_t _wide_data;
    __uint32_t _freeres_list;
    __uint32_t _freeres_buf;
    __uint32_t __pad5;
    __uint32_t _mode;
    char _unused2[0x28];
    VTABLE_JUMP *_vtable_jump;
} CFILE;