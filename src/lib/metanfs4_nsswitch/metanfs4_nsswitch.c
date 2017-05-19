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

int             _nss_metanfs4_udx   = 0;
int             _nss_metanfs4_gdx   = 0;

/* -------------------------------------------------------------------------- */

NSS_STATUS _setup_item(char **buffer, size_t *buflen,char** dest, const char* source, int *errnop)
{
    int len;

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

NSS_STATUS 
_nss_metanfs4_setpwent(void)
{
    _nss_metanfs4_udx = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{  
    char*       name;
    NSS_STATUS  ret;

    _nss_metanfs4_udx++;
    name = enumerate_name(_nss_metanfs4_udx);
    if( name != NULL ){
        ret = _nss_metanfs4_getpwnam_r(name,result,buffer,buflen,errnop);
        free(name);
        if( ret != NSS_STATUS_SUCCESS ) _nss_metanfs4_udx--;
        return(ret);
    }

    *errnop = ENOENT;
    return(NSS_STATUS_NOTFOUND);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_endpwent(void)
{  
    _nss_metanfs4_udx = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_setgrent(void)
{  
    _nss_metanfs4_gdx = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    char*       name;
    NSS_STATUS  ret;

    _nss_metanfs4_gdx++;

    name = enumerate_group(_nss_metanfs4_gdx);
    if( name != NULL ){
        ret = _nss_metanfs4_getgrnam_r(name,result,buffer,buflen,errnop);
        free(name);
        if( ret != NSS_STATUS_SUCCESS ) _nss_metanfs4_gdx--;
        return(ret);
    }

    *errnop = ENOENT;
    return(NSS_STATUS_NOTFOUND);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS 
_nss_metanfs4_endgrent(void)
{   
    _nss_metanfs4_gdx = 0;
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

    if( name == NULL ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    uid = get_uid(name);
    if( uid <= 0 ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid("METANFS4");
    if( gid <= 0 ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
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

    *errnop = 0;
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
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }
    if( ret > 0 ){
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }

    gid = get_gid("METANFS4");
    if( gid <= 0 ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
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

    *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */

NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    int     gid,id,i,ret,len;
    char*   p_mem_names;
    char**  p_mem_list;

    if( name == NULL ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    if( strstr(name,"@") == NULL ){
        /* avoid infinitive loop with idmap */
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    gid = get_gid(name);
    if( gid <= 0 ){
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }

    /* fill the structure */
    ret = _setup_item(&buffer,&buflen,&(result->gr_name),name,errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);

    ret = _setup_item(&buffer,&buflen,&(result->gr_passwd),"x",errnop);
    if( ret != NSS_STATUS_SUCCESS ) return(ret);
    result->gr_gid = gid;

    /* members */
    if( sizeof(char*) > buflen ){
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }
    p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(name,id,buffer,buflen);
        if( ret > 0 ){
            *errnop = ERANGE;
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
            *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        len = strlen(p_mem_names) + 1;
        p_mem_names += len;
    }
    if( sizeof(char*) > buflen ){
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }  
    *p_mem_list = NULL;
    
    *errnop = 0;
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
        *errnop = ENOENT;
        return(NSS_STATUS_NOTFOUND);
    }
    if( ret > 0 ){
        *errnop = ERANGE;
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
    if( sizeof(char*) > buflen ){
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }
    p_mem_names = buffer;
    id = 0;
    do{
        ret = get_group_member(result->gr_name,id,buffer,buflen);
        if( ret > 0 ){
            *errnop = ERANGE;
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
            *errnop = ERANGE;
            return(NSS_STATUS_TRYAGAIN);
        }
        *p_mem_list = p_mem_names;
        buflen -= sizeof(char*);
        p_mem_list++;
        len = strlen(p_mem_names) + 1;
        p_mem_names += len;
    }
    if( sizeof(char*) > buflen ){
        *errnop = ERANGE;
        return(NSS_STATUS_TRYAGAIN);
    }  
    *p_mem_list = NULL;    

    *errnop = 0;
    return(NSS_STATUS_SUCCESS);
}

/* -------------------------------------------------------------------------- */
