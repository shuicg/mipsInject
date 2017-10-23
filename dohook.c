#include <stdio.h>

int dohook()
{
    printf("inject success,in dohook!");
    return 0xabc;
}
