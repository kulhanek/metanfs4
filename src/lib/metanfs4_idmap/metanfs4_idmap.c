#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <common.h>
#include <metanfs4_idmap.h>

/* -----------------------------------------------------------------------------
// #############################################################################
// -------------------------------------------------------------------------- */

struct trans_func nss_trans;

/* -------------------------------------------------------------------------- */

DLL_EXPORT
struct trans_func *libnfsidmap_plugin_init()
{
    nss_trans.name           = "metanfs4";
    nss_trans.init           = NULL;

    /* idmap  */
    nss_trans.name_to_uid    = idmap_get_uid;
    nss_trans.name_to_gid    = idmap_get_gid;
    nss_trans.uid_to_name    = uid_to_name;
    nss_trans.gid_to_name    = gid_to_name;

     /* krb5 */
    nss_trans.princ_to_ids   = princ_to_ids;
    nss_trans.gss_princ_to_grouplist = gss_princ_to_grouplist;

    return (&nss_trans);
}

/* -----------------------------------------------------------------------------
// #############################################################################
// -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_get_uid(char* name,uid_t* uid)
{
    struct SNFS4Message msg;
    struct passwd*      p_pwd;

    memset(&msg,0,sizeof(msg));

    msg.Type = MSG_IDMAP_REG_NAME;
    strncpy(msg.Name,name,MAX_NAME);

    if( exchange_data(&msg) != 0 ) return(-ENOENT);

    if( msg.ID.UID > 0 ){
        (*uid) = msg.ID.UID;
        return(0);
    }

    /* ask for local uid */
    p_pwd = getpwnam(msg.Name);  /* data.Name contains local name */
    if( p_pwd != NULL ){
        (*uid) = p_pwd->pw_uid;
        return(0);
    }

    /* return nobody - already received in datagram */
    (*uid) = msg.Extra.UID;
    return(0);
}
/* -------------------------------------------------------------------------- */

DLL_LOCAL
int idmap_get_gid(char *name, uid_t *gid)
{
    struct SNFS4Message msg;
    struct group*       p_grp;

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_IDMAP_REG_GROUP;
    strncpy(msg.Name,name,MAX_NAME);

    if( exchange_data(&msg) != 0 ) return(-ENOENT);

    if( msg.ID.GID > 0 ){
        (*gid) = msg.ID.GID;
        return(0);
    }

    /* ask for local gid */
    p_grp = getgrnam(msg.Name);   /* data.Name contains local name */
    if( p_grp != NULL ){
        (*gid) = p_grp->gr_gid;
        return(0);
    }

    /* return nogroup - already received in datagram */
    (*gid) = msg.Extra.GID;
    return(0);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
    struct passwd *p_pwd = getpwuid(uid);
    if( p_pwd == NULL ) return(-ENOENT);

    return( idmap_user_to_local_domain(p_pwd->pw_name,name,len) );
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
    struct group *p_grp = getgrgid(gid);
    if( p_grp == NULL )return(-ENOENT);

    return( idmap_group_to_local_domain(p_grp->gr_name,name,len) );
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex)
{
    struct SNFS4Message msg;

    /* check allowed security contexts */
    if (strcmp(secname, "spkm3") == 0) return(-ENOENT);
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_IDMAP_PRINC_TO_ID;
    strncpy(msg.Name,princ,MAX_NAME);

    if( exchange_data(&msg) != 0 ) return(-ENOENT);

    (*uid) = msg.ID.UID;
    (*gid) = msg.Extra.GID;
    return(0);
}

/* -------------------------------------------------------------------------- */

DLL_LOCAL
int gss_princ_to_grouplist(char *secname, char *princ, gid_t *groups,
                           int *ngroups, extra_mapping_params **ex)
{
    struct SNFS4Message msg;

    /* check allowed security contexts */
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    memset(&msg,0,sizeof(msg));
    msg.Type = MSG_IDMAP_PRINC_TO_ID;
    strncpy(msg.Name,princ,MAX_NAME);

    if( exchange_data(&msg) != 0 ) return(-ENOENT);

    if (getgrouplist(msg.Name, msg.Extra.GID, groups, ngroups) < 0) return(-ERANGE);

    return(0);
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

