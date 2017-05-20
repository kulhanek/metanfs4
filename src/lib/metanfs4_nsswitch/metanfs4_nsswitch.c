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
#include <metanfs4_nsswitch.h>

/*
  Documentation:
  https://www.gnu.org/software/libc/manual/html_node/Extending-NSS.html#Extending-NSS

  sigv?
  https://github.com/lattera/glibc/blob/master/grp/compat-initgroups.c
  in

#0  __GI___libc_free (mem=mem@entry=0x4037376a6f6b7261) at malloc.c:2929
        ar_ptr = <optimized out>
        p = <optimized out>
        hook = 0x0
#1  0x00007fd6486eda69 in compat_call (nip=<optimized out>, user=<optimized out>, group=4281413, start=0x64656d6968637261, size=0x4154454d407573, groupsp=0x617261004154454d, limit=6989658451874758772, errnop=<optimized out>) at compat-initgroups.c:120
        grpbuf = {gr_name = 0x6d7261004154454d <error: Cannot access memory at address 0x6d7261004154454d>, gr_passwd = 0x454d406b6564616c <error: Cannot access memory at address 0x454d406b6564616c>, gr_gid = 1627406676, gr_mem = 0x61004154454d4074}
        buflen = <optimized out>
        status = <optimized out>
        setgrent_fct = <optimized out>
        getgrent_fct = 0x7fd6475910eb <_setup_item+86>
        endgrent_fct = 0x40796b7375686172
        groups = <optimized out>
        tmpbuf = 0x4037376a6f6b7261 <error: Cannot access memory at address 0x4037376a6f6b7261>
        use_malloc = 77
        result = NSS_STATUS_SUCCESS


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
    static char*        ptr = NULL;

    *errnop = ENOENT;

    if( exchange_data(p_msg) != 0 ) return(NSS_STATUS_NOTFOUND);
    if( p_msg->ID.GID == 0 ) return(NSS_STATUS_NOTFOUND);

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->gr_name),p_msg->Name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->gr_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->gr_gid = p_msg->ID.GID;

    /* members */
    result->gr_mem = &ptr;

    *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */
