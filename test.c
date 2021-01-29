

#include <stdio.h>

int main()
{
    printf("Result: %c\n", 0xcd < 0x31
                               ? '1'
                               : '0');
}