

#include <stdio.h>
#include <stdlib.h>

int main()
{
    char *sh = "/bin/sh";
    printf("hello world!%s", "%p");

    system(sh);
    return 0; 
}