#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "metanfs4d.hpp"

// -----------------------------------------------------------------------------

int main(int argc,char* argv[])
{
    if( argc != 2 ){
        printf("one argument required\n");
        return(-1);
    }

    int clisckt = socket(AF_UNIX,SOCK_STREAM,0);
    if( clisckt == -1 ){
        printf("unable to create socket\n");
        return(1);
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    int addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 ){
        printf("unable to connect to %s - errno %s\n",SERVERNAME,strerror(errno));
        return(1);
    }

    // complete message
    struct msghdr       msg;
    struct iovec        iov[1];
    struct SNFS4Message data;

    iov[0].iov_base = &data;
    iov[0].iov_len = sizeof(data);

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_NAME_TO_ID;
    strncpy(data.Name,argv[1],MAX_NAME);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = 0;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    if( sendmsg(clisckt,&msg,0) == -1 ){
        printf("unable to send msg\n");
        return(1);
    }

    memset(&data,0,sizeof(data));

    if( recvmsg(clisckt,&msg,0) == -1 ){
        printf("unable to send msg\n");
        close(clisckt);
        return(1);
    }

    if( data.Type != MSG_IDMAP_NAME_TO_ID ){
        printf("wrong response - %d\n",data.Type);
        close(clisckt);
        return(1);
    }

    printf("user id: %d\n",data.ID);

    close(clisckt);

    return(0);
}

// -----------------------------------------------------------------------------
