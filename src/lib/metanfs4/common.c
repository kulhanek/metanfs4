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

    if( p_msg->Type == type) return(0);

    return(-1);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_get_princ_uid(const char* name)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_PRINC_TO_ID;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-1);

    return(data.ID);
}
       
/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_get_uid(const char* name)
{
    struct SNFS4Message data;
    struct passwd*      p_pwd;

    memset(&data,0,sizeof(data));
    
    data.Type = MSG_IDMAP_REG_NAME;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-1);

    if( data.ID > 0 ) return(data.ID);
    
    data.Name[MAX_NAME] = '\0';

    /* ask for local uid */
    p_pwd = getpwnam(data.Name);  /* data.Name contains local name */
    if( p_pwd != NULL ){
        return(p_pwd->pw_uid);
    }
    
    /* ask for NOBODY */
    return(get_uid("NOBODY"));
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_get_gid(const char* name)
{
    struct SNFS4Message data;
    struct group*       p_grp;

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_REG_GROUP;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-1);

    if( data.ID > 0 ) return(data.ID);
    
    data.Name[MAX_NAME] = '\0';

    /* ask for local gid */
    p_grp = getgrnam(data.Name);   /* data.Name contains local name */
    if( p_grp != NULL ){
        return(p_grp->gr_gid);
    }
    
    /* ask for NOGROUP */
    return(get_gid("NOGROUP"));
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

DLL_LOCAL
int get_uid(const char* name)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_NAME_TO_ID;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-1);

    return(data.ID);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int get_gid(const char* name)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_GROUP_TO_ID;
    strncpy(data.Name,name,MAX_NAME);

    if( exchange_data(&data) != 0 ) return(-1);

    return(data.ID);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int get_name(int id,char* name,int bufflen)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_ID_TO_NAME;
    data.ID = id;

    if( exchange_data(&data) != 0 ) return(-1);
    
    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int get_group(int id,char* name,int bufflen)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_ID_TO_GROUP;
    data.ID = id;

    if( exchange_data(&data) != 0 ) return(-1);
    
    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int get_group_member(const char* gname,int id,char* name,int bufflen)
{
    struct SNFS4Message data;

    memset(&data,0,sizeof(data));
    data.Type = MSG_GROUP_MEMBER;
    strncpy(data.Name,gname,MAX_NAME);
    data.ID = id;

    if( exchange_data(&data) != 0 ) return(-1);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);
    
    return(0);
}

/* -------------------------------------------------------------------------- */

/* returned string must be freed by free() */
DLL_LOCAL
char* enumerate_name(int id)
{
    struct SNFS4Message data;
    char*               name;

    memset(&data,0,sizeof(data));
    data.Type = MSG_ENUM_NAME;
    data.ID = id;

    if( exchange_data(&data) != 0 ) return(NULL);

    if( data.ID != id ) return(NULL); /* end of records */

    data.Name[MAX_NAME] = '\0';
    name = (char*)malloc(strlen(data.Name)+1);
    strcpy(name,data.Name);

    return(name);
}

/* -------------------------------------------------------------------------- */

/* returned string must be freed by free() */
DLL_LOCAL
char* enumerate_group(int id)
{
    struct SNFS4Message data;
    char*               name;

    memset(&data,0,sizeof(data));
    data.Type = MSG_ENUM_GROUP;
    data.ID = id;

    if( exchange_data(&data) != 0 ) return(NULL);

    if( data.ID != id ) return(NULL); /* end of records */

    data.Name[MAX_NAME] = '\0';
    name = (char*)malloc(strlen(data.Name)+1);
    strcpy(name,data.Name);

    return(name);
}

/* -------------------------------------------------------------------------- */


