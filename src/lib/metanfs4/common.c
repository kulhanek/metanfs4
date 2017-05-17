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
#include "common.h"

/* -------------------------------------------------------------------------- */

int idmap_get_princ_uid(const char* name)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX,SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_IDMAP_PRINC_TO_ID;
    strncpy(data.Name,name,MAX_NAME);    

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    if( data.Type != MSG_IDMAP_PRINC_TO_ID ) {
        close(clisckt);
        return(-ENOENT);
    }

    close(clisckt);

    return(data.ID);
}
       
/* -------------------------------------------------------------------------- */

int idmap_get_uid(const char* name)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;
    struct passwd       *p_pwd;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));
    
    data.Type = MSG_IDMAP_REG_NAME;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_IDMAP_REG_NAME ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);

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

int idmap_get_gid(const char* name)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;
    struct group        *p_grp;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_REG_GROUP;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_IDMAP_REG_GROUP ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);

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

int idmap_user_to_local_domain(const char* name, char* lname, int len)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-ENOENT);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-ENOENT);

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_USER_TO_LOCAL_DOMAIN;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    if( data.Type != MSG_IDMAP_USER_TO_LOCAL_DOMAIN ) {
        close(clisckt);
        return(-ENOENT);
    }

    close(clisckt);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > len ) return(-ERANGE);
    strcpy(lname,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

int idmap_group_to_local_domain(const char* name, char* lname, int len)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-ENOENT);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-ENOENT);

    memset(&data,0,sizeof(data));
    data.Type = MSG_IDMAP_GROUP_TO_LOCAL_DOMAIN;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-ENOENT);
    }

    if( data.Type != MSG_IDMAP_GROUP_TO_LOCAL_DOMAIN ) {
        close(clisckt);
        return(-ENOENT);
    }

    close(clisckt);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > len ) return(-ERANGE);
    strcpy(lname,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

int get_uid(const char* name)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_NAME_TO_ID;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_NAME_TO_ID ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);

    return(data.ID);
}

/* -------------------------------------------------------------------------- */

int get_gid(const char* name)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_GROUP_TO_ID;
    strncpy(data.Name,name,MAX_NAME);

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_GROUP_TO_ID ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);

    return(data.ID);
}

/* -------------------------------------------------------------------------- */

int get_name(int id,char* name,int bufflen)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_ID_TO_NAME;
    data.ID = id;

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_ID_TO_NAME ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);
    
    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

int get_group(int id,char* name,int bufflen)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_ID_TO_GROUP;
    data.ID = id;

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_ID_TO_GROUP ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);
    
    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);

    return(0);
}

/* -------------------------------------------------------------------------- */

int get_group_member(const char* gname,int id,char* name,int bufflen)
{
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(-1);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(-1);

    memset(&data,0,sizeof(data));

    data.Type = MSG_GROUP_MEMBER;
    strncpy(data.Name,gname,MAX_NAME);
    data.ID = id;

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(-1);
    }

    if( data.Type != MSG_GROUP_MEMBER ) {
        close(clisckt);
        return(-1);
    }

    close(clisckt);

    data.Name[MAX_NAME] = '\0';
    if( strlen(data.Name) + 1 > bufflen ) return(1); /* out of memory */
    strcpy(name,data.Name);
    
    return(0);
}

/* -------------------------------------------------------------------------- */

char* enumerate_name(int id)
{
    static char         name[MAX_NAME+1];    
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(NULL);

    memset(&address, 0, sizeof(struct sockaddr_un));
    memset(name,0,MAX_NAME+1);

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(NULL);

    memset(&data,0,sizeof(data));

    data.Type = MSG_ENUM_NAME;
    data.ID = id;

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(NULL);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(NULL);
    }

    if( data.Type != MSG_ENUM_NAME ) {
        close(clisckt);
        return(NULL);
    }

    close(clisckt);

    if( data.ID != id ) return(NULL); /* end of records */

    strncpy(name,data.Name,MAX_NAME);

    return(name);
}

/* -------------------------------------------------------------------------- */

char* enumerate_group(int id)
{
    static char         name[MAX_NAME+1];     
    struct sockaddr_un  address;
    struct SNFS4Message data;
    int                 addrlen;

    int clisckt = socket(AF_UNIX, SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(NULL);

    memset(&address, 0, sizeof(struct sockaddr_un));
    memset(name,0,MAX_NAME+1);

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 )  return(NULL);

    memset(&data,0,sizeof(data));

    data.Type = MSG_ENUM_GROUP;
    data.ID = id;

    if( write(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(NULL);
    }

    memset(&data,0,sizeof(data));

    if( read(clisckt,&data,sizeof(data)) != sizeof(data) ){
        close(clisckt);
        return(NULL);
    }

    if( data.Type != MSG_ENUM_GROUP ) {
        close(clisckt);
        return(NULL);
    }

    close(clisckt);

    if( data.ID != id ) return(NULL); /* end of records */

    strncpy(name,data.Name,MAX_NAME);

    return(name);
}

/* -------------------------------------------------------------------------- */


