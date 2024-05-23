#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    int x = 0;

    for(;;){
        x = x + 1;
    }

    exit(0);
    return 0;
}
