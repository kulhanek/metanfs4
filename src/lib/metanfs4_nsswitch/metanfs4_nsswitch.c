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
    pwdbid++;    
    char* name = enumerate_name(pwdbid);
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
    grdbid++;    
    char* name = enumerate_group(grdbid);
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
    int gid;
    int uid;

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    uid = get_uid(name);

    if( uid <= 0 ){
        if( errnop ) *errnop = 1;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid("NOGROUP");
    if( gid <= 0 ){
        gid = -1;
    }
    
    if( strlen(name) + 1 > buflen ) {
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }    
    strcpy(buffer, name);
    result->pw_name = buffer;
    buffer += strlen(buffer) + 1;
    buflen -= strlen(buffer) + 1;    

    result->pw_passwd = "x";
    result->pw_uid = uid;
    result->pw_gid = gid;
    /* gecos cannot be null on Ubuntu 12.04 as it crashes nscd daemon */
    result->pw_gecos = result->pw_name;
    result->pw_dir = "/dev/null";
    result->pw_shell = "/dev/null";

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop)
{  
    int gid;
    int ret;
    
    ret = get_name(uid,buffer,buflen);
    if( ret != 0 ){
        if( errnop && (ret < 0) ) *errnop = ENOENT;
        if( errnop && (ret > 0) ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }
    
    gid = get_gid("NOGROUP");
    if( gid <= 0 ){
        gid = -1;
    }

    result->pw_name = buffer;
    buffer += strlen(buffer) + 1;
    buflen -= strlen(buffer) + 1;
    
    result->pw_passwd = "x";
    result->pw_uid = uid;
    result->pw_gid = gid;
    /* gecos cannot be null on Ubuntu 12.04 as it crashes nscd daemon */
    result->pw_gecos = result->pw_name;
    result->pw_dir = "/dev/null";
    result->pw_shell = "/dev/null";

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int gid,id,i,ret;

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        if( errnop ) *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid(name);
    if( gid <= 0 ){
        if( errnop ) *errnop = 1;
        return(NSS_STATUS_NOTFOUND);
    }

    if( strlen(name) + 1 > buflen ) {
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }
    strcpy(buffer,name);
    result->gr_name = buffer;
    buffer += strlen(buffer) + 1;
    buflen -= strlen(buffer) + 1;
    
    result->gr_passwd = "x";
    result->gr_gid = gid;
    
    // members
    char* p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(name,id,buffer,buflen);
        if( ret > 0 ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_NOTFOUND);
        }
        if( ret == 0 ){ 
            id++;
            buffer += strlen(buffer) + 1;
            buflen -= strlen(buffer) + 1;
        }
    } while( ret == 0 );
    
    char** p_mem_list = (char**)buffer;
    result->gr_mem = p_mem_list;    
    for(i=0; i < id; i++){
        if( sizeof(char*) > buflen ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_NOTFOUND);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        p_mem_names += strlen(p_mem_names) + 1;
    }
    if( sizeof(char*) > buflen ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }  
    *p_mem_list = NULL;
    
    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int id,i;
    
    int ret;
    ret = get_group(gid,buffer,buflen);
    if( ret != 0 ){
        if( errnop && (ret < 0) ) *errnop = ENOENT;
        if( errnop && (ret > 0) ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }

    result->gr_name = buffer;
    buffer += strlen(buffer) + 1;
    buflen -= strlen(buffer) + 1;
    
    result->gr_passwd = "x";
    result->gr_gid = gid;

    // members
    char* p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(result->gr_name,id,buffer,buflen);
        if( ret > 0 ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_NOTFOUND);
        }
        if( ret == 0 ){ 
            id++;
            buffer += strlen(buffer) + 1;
            buflen -= strlen(buffer) + 1;
        }
    } while( ret == 0 );
    
    char** p_mem_list = (char**)buffer;
    result->gr_mem = p_mem_list;    
    for(i=0; i < id; i++){
        if( sizeof(char*) > buflen ){
            if( errnop ) *errnop = ERANGE;
            return(NSS_STATUS_NOTFOUND);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        p_mem_names += strlen(p_mem_names) + 1;
    }
    if( sizeof(char*) > buflen ){
        if( errnop ) *errnop = ERANGE;
        return(NSS_STATUS_NOTFOUND);
    }  
    *p_mem_list = NULL;    

    if( errnop ) *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */
