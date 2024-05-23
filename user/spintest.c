#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/pstat.h"

int
main(int argc, char *argv[])
{
  
    if(argc != 2){
        printf("usage: mytest counter");
        exit(0);
    }

    int x;
    for(int i = 1; i < atoi(argv[1]); i++){
        x = x + i;
    }
    
    struct pstat st;
    procinfo(&st);
    int mypid = getpid();
    for (int j = 0; j < 64; j++) {
        if (st.inuse[j] == 1 && st.pid[j] >= 3 && st.pid[j] == mypid) {
            for (int l = 0; l < 4; l++) {
                printf("level:%d \t ticks-used:%d\n", l, st.ticks[j][l]);
            }
        }
    }
    

    exit(0);
    return 0;
}
