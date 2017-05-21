#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <string.h>
#include <pthread.h>
#include <common.h>
#include <sys/socket.h>
#include <stddef.h>
#include <metanfs4_nsswitch.h>

/*
  Documentation:
  https://www.gnu.org/software/libc/manual/html_node/Extending-NSS.html#Extending-NSS

*/

/* -------------------------------------------------------------------------- */
/*
    http://man7.org/linux/man-pages/man3/getpwent.3.html
    MT-Unsafe:
    struct passwd *getpwent(void);
    void setpwent(void);
    void endpwent(void);
*/

DLL_LOCAL int             _nss_metanfs4_udx   = 0;
DLL_LOCAL int             _nss_metanfs4_gdx   = 0;

/* -------------------------------------------------------------------------- */

DLL_LOCAL NSS_STATUS
_setup_item(char **buffer, size_t *buflen,char** dest, const char* source, int *errnop)
{
    size_t len;

    len = strlen(source) + 1;

    /* do we have space? */
    if( len > *buflen ) {
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }

    /* copy data and shift in the buffer */
    strcpy(*buffer,source);
    (*dest) = (*buffer);
    (*buffer) += len;
    (*buflen) -= len;

    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_setpwent(void)
{
    _nss_metanfs4_udx = 1;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{     
    NSS_STATUS          ret;
    struct SNFS4Message msg;

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_ENUM_NAME;
    msg.ID.UID = _nss_metanfs4_udx;

    ret = _nss_metanfs4_getpasswd(&msg,result,buffer,buflen,errnop);
    if( ret == NSS_STATUS_SUCCESS )  _nss_metanfs4_udx++;

    return(ret);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_endpwent(void)
{  
    _nss_metanfs4_udx = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_setgrent(void)
{  
    _nss_metanfs4_gdx = 1;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    NSS_STATUS          ret;
    struct SNFS4Message msg;

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_ENUM_GROUP;
    msg.ID.GID = _nss_metanfs4_gdx;

    ret = _nss_metanfs4_getgroup(&msg,result,buffer,buflen,errnop);
    if( ret == NSS_STATUS_SUCCESS )  _nss_metanfs4_gdx++;

    return(ret);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_endgrent(void)
{   
    _nss_metanfs4_gdx = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getpwnam_r(const char *name, struct passwd *result,
                     char *buffer, size_t buflen, int *errnop)
{
    struct SNFS4Message msg;

    *errnop = ENOENT;

    if( name == NULL ) return(NSS_STATUS_NOTFOUND);

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        return(NSS_STATUS_NOTFOUND);
    }

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_NAME_TO_ID;
    strncpy(msg.Name,name,MAX_NAME);

    return(_nss_metanfs4_getpasswd(&msg,result,buffer,buflen,errnop));
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop)
{  
    struct SNFS4Message msg;

    *errnop = ENOENT;

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_ID_TO_NAME;
    msg.ID.UID = uid;

    return(_nss_metanfs4_getpasswd(&msg,result,buffer,buflen,errnop));
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    struct SNFS4Message msg;

    *errnop = ENOENT;

    if( name == NULL ) return(NSS_STATUS_NOTFOUND);

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        return(NSS_STATUS_NOTFOUND);
    }

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_GROUP_TO_ID;
    strncpy(msg.Name,name,MAX_NAME);

    return(_nss_metanfs4_getgroup(&msg,result,buffer,buflen,errnop));
}

/* -------------------------------------------------------------------------- */

DLL_EXPORT NSS_STATUS
_nss_metanfs4_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    struct SNFS4Message msg;

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_ID_TO_GROUP;
    msg.ID.GID = gid;

    return(_nss_metanfs4_getgroup(&msg,result,buffer,buflen,errnop));
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL  NSS_STATUS
_nss_metanfs4_getpasswd(struct SNFS4Message* p_msg, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop)
{
    NSS_STATUS  ret;

    *errnop = ENOENT;

    if( exchange_data(p_msg) != 0 ) return(NSS_STATUS_NOTFOUND);
    if( p_msg->ID.UID == 0 ) return(NSS_STATUS_NOTFOUND);

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->pw_name),p_msg->Name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->pw_uid = p_msg->ID.UID;
    result->pw_gid = p_msg->Extra.GID;
    ret = _setup_item(&buffer,&buflen,&(result->pw_gecos),result->pw_name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_dir),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_shell),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);

    *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL NSS_STATUS
_nss_metanfs4_getgroup(struct SNFS4Message* p_msg, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    NSS_STATUS          ret;
    struct sockaddr_un  address;
    socklen_t           addrlen;
    size_t              numofmems;
    size_t              memlen;
    size_t              len;
    char*               p_member;
    int                 type,i;
    int                 clisckt;

    *errnop = ENOENT;
    if( p_msg == NULL ) return(NSS_STATUS_NOTFOUND);

    clisckt = socket(AF_UNIX,SOCK_SEQPACKET,0);
    if( clisckt == -1 ) return(NSS_STATUS_NOTFOUND);

    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);

    addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1;

    if( connect(clisckt,(struct sockaddr *) &address, addrlen) == -1 ){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }

    type = p_msg->Type;

    if( write(clisckt,p_msg,sizeof(struct SNFS4Message)) != sizeof(struct SNFS4Message) ){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }

    memset(p_msg,0,sizeof(struct SNFS4Message));

    if( read(clisckt,p_msg,sizeof(struct SNFS4Message)) != sizeof(struct SNFS4Message) ){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }

    /* ensure \0 termination of the string */
    p_msg->Name[MAX_NAME] = '\0';

    if( p_msg->Type != type){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }

    if( p_msg->ID.GID == 0 ){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->gr_name),p_msg->Name,errnop);
    if( ret != NSS_STATUS_SUCCESS ){
        close(clisckt);
        return(ret);
    }
    ret = _setup_item(&buffer,&buflen,&(result->gr_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ){
        close(clisckt);
        return(ret);
    }
    result->gr_gid = p_msg->ID.GID;

    /* read members */
    memlen = p_msg->Len; /* zero terminated names */
    numofmems = p_msg->Extra.GID; /* number of mebers */

    p_member = buffer;

    if( memlen + sizeof(char*)*(numofmems+1) > buflen ) {
        *errnop = ERANGE;
        close(clisckt);
        return(NSS_STATUS_TRYAGAIN);
    }
    if( read(clisckt,buffer,memlen) != memlen ){
        close(clisckt);
        return(NSS_STATUS_NOTFOUND);
    }
    close(clisckt);

    buffer += memlen;
    buflen -= memlen;

    result->gr_mem = (char**)buffer;

    i = 0;
    while(i < numofmems){
        result->gr_mem[i] =  p_member;
        len = strlen(p_member) + 1;
        p_member += len;
        i++;
    }
    result->gr_mem[i] =  NULL;

    *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */
