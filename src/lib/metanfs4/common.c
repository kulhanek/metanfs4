#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <nss.h>
#include <errno.h>
#include <stddef.h>
#include "common.h"

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int exchange_data(struct SNFS4Message* p_msg)
{
    struct sockaddr_un  address;
    socklen_t           addrlen;
    int                 type;
    int                 clisckt;

    if( p_msg == NULL ) return(-1);

    clisckt = socket(AF_UNIX,SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);

    addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1;

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    type = p_msg->Type;

    if( write(clisckt,p_msg,sizeof(struct SNFS4Message)) != sizeof(struct SNFS4Message) ){
        close(clisckt);
        return(-1);
    }

    memset(p_msg,0,sizeof(struct SNFS4Message));

    if( read(clisckt,p_msg,sizeof(struct SNFS4Message)) != sizeof(struct SNFS4Message) ){
        close(clisckt);
        return(-1);
    }

    close(clisckt);

    /* ensure \0 termination of the string */
    p_msg->Name[MAX_NAME] = '\0';

    if( p_msg->Type == type) return(0);

    return(-1);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_user_to_local_domain(const char* name, char* lname, int len)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_USER_TO_LOCAL_DOMAIN;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-ENOENT);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > len ) return(-ERANGE);
    strcpy(lname,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_group_to_local_domain(const char* name, char* lname, int len)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_GROUP_TO_LOCAL_DOMAIN;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-ENOENT);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > len ) return(-ERANGE);
    strcpy(lname,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */


