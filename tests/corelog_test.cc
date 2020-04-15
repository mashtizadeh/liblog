
#include <sys/types.h>

#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <debug.h>
#include <corelog.h>

#define LOGSIZE (1024*1024)

int
main(int argc, char *argv[])
{
    int i;
    char *buf;

    printf("Testing the CoreLog.\n");

    buf = (char *)malloc(LOGSIZE);
    assert(buf != 0);

    CoreLog_Init(buf, LOGSIZE, "testlog1");

    for (i = 0; i < 1000000; i++)
    {
        CoreLog_Log(0, "Testing %d\n", i);
    }

    abort();

    CoreLog_Destroy();

    return 0;
}

