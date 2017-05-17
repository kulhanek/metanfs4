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
#include "common.h"

#define NSS_STATUS enum nss_status

/* -------------------------------------------------------------------------- */

static int pwdbid = 0;
static int grdbid = 0;

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result, 
                    char *buffer, size_t buflen, int *errnop);
NSS_STATUS
_nss_metanfs4_getpwnam_r(const char *name, struct passwd *result,
                    char *buffer, size_t buflen, int *errnop);


/* -------------------------------------------------------------------------- */

NSS_STATUS _setup_item(char **buffer, size_t *buflen,char** dest, const char* source, int *errnop)
{
    int len;

    if( strlen(source) + 1 > *buflen ) {
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }

    strcpy(*buffer,source);
    *dest = *buffer;
    len = strlen(*buffer) + 1;
    *buffer += len;
    *buflen -= len;

    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_setpwent(void)
{
    pwdbid = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{  
    char* name;

    pwdbid++;    
    name = enumerate_name(pwdbid);
    if( name != NULL ){
        return(_nss_metanfs4_getpwnam_r(name,result,buffer,buflen,errnop));
    }
    return(NSS_STATUS_NOTFOUND);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_endpwent(void)
{  
    pwdbid = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_setgrent(void)
{  
    grdbid = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    char* name;

    grdbid++;    
    name = enumerate_group(grdbid);
    if( name != NULL ){
        return(_nss_metanfs4_getgrnam_r(name,result,buffer,buflen,errnop));
    }
    return(NSS_STATUS_NOTFOUND);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_endgrent(void)
{   
    grdbid = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getpwnam_r(const char *name, struct passwd *result,
                     char *buffer, size_t buflen, int *errnop)
{
    int         gid;
    int         uid;
    NSS_STATUS  ret;

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    uid = get_uid(name);
    if( uid <= 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid("METANFS4");
    if( gid <= 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_UNAVAIL);
    }

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->pw_name),name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->pw_uid = uid;
    result->pw_gid = gid;
    ret = _setup_item(&buffer,&buflen,&(result->pw_gecos),result->pw_name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_dir),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_shell),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop)
{  
    int         gid;
    int         len;
    NSS_STATUS  ret;
    
    ret = get_name(uid,buffer,buflen);
    if( ret < 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }
    if( ret > 0 ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }

    gid = get_gid("METANFS4");
    if( gid <= 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_UNAVAIL);
    }

    /* fill the structure */
    result->pw_name = buffer;
    len = strlen(buffer) + 1;
    buffer += len;
    buflen -= len;
    ret = _setup_item(&buffer,&buflen,&(result->pw_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->pw_uid = uid;
    result->pw_gid = gid;
    ret = _setup_item(&buffer,&buflen,&(result->pw_gecos),result->pw_name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_dir),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    ret = _setup_item(&buffer,&buflen,&(result->pw_shell),"/dev/null",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int     gid,id,i,ret,len;
    char*   p_mem_names;
    char**  p_mem_list;

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid(name);
    if( gid <= 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->gr_name),name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);

    ret = _setup_item(&buffer,&buflen,&(result->gr_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->gr_gid = gid;

    /* members */
    p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(name,id,buffer,buflen);
        if( ret > 0 ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        if( ret == 0 ){ 
            id++;
            len = strlen(buffer) + 1;
            buffer += len;
            buflen -= len;
        }
    } while( ret == 0 );
    
    p_mem_list = (char**)buffer;
    result->gr_mem = p_mem_list;    
    for(i=0; i < id; i++){
        if( sizeof(char*) > buflen ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        len = strlen(p_mem_names) + 1;
        p_mem_names += len;
    }
    if( sizeof(char*) > buflen ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }  
    *p_mem_list = NULL;
    
    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int     id,i,len;
    char*   p_mem_names;
    char**  p_mem_list;
    
    int ret;
    ret = get_group(gid,buffer,buflen);
    if( ret < 0 ){
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }
    if( ret > 0 ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }

    /* fill the structure */
    result->gr_name = buffer;
    len = strlen(buffer) + 1;
    buffer += len;
    buflen -= len;

    ret = _setup_item(&buffer,&buflen,&(result->gr_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->gr_gid = gid;

    /* members */
    p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(result->gr_name,id,buffer,buflen);
        if( ret > 0 ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        if( ret == 0 ){ 
            id++;
            len = strlen(buffer) + 1;
            buffer += len;
            buflen -= len;
        }
    } while( ret == 0 );
    
    p_mem_list = (char**)buffer;
    result->gr_mem = p_mem_list;    
    for(i=0; i < id; i++){
        if( sizeof(char*) > buflen ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        len = strlen(p_mem_names) + 1;
        p_mem_names += len;
    }
    if( sizeof(char*) > buflen ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }  
    *p_mem_list = NULL;    

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */
