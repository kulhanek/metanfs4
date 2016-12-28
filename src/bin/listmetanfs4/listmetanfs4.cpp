#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <fstream>
#include <map>
#include <pwd.h>
#include <grp.h>

extern "C" {
#include "metanfs4d.hpp"
}

// -----------------------------------------------------------------------------

int main(void)
{
    std::ifstream fin;

    // load predefined groups
    fin.open(STATIC_GROUPS);
    int num = 0;
    printf("Static groups:\n");
    while( fin ){
        std::string group;
        fin >> group;
        if( ! group.empty() ){
            printf("  %s\n",group.c_str());
            num++;
        }
    }
    fin.close();
    printf("Number of items: %d\n",num);
    printf("----------------------------------------\n");

    int nusrs = 0;
    int ngrps = 0;
    printf("Users:\n");
    for(int i=1; i < MAX_RECORDS; i++){
        char* name = enumerate_name(i);
        if( name == NULL ) break;
        printf("  %s\n",name);
        nusrs++;
    }
    printf("----------------------------------------\n");
    printf("Groups:\n");
    for(int i=1; i < MAX_RECORDS; i++){
        char* name = enumerate_group(i);
        if( name == NULL ) break;
        printf("  %s\n",name);
        ngrps++;
    }
    printf("----------------------------------------\n");
    printf("Number of users:  %d\n",nusrs);
    printf("Number of groups: %d\n",ngrps);
    return(0);
}

// -----------------------------------------------------------------------------
