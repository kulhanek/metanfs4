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

struct trans_func *libnfsidmap_plugin_init()
{
    nss_trans.name           = "metanfs4";
    nss_trans.init           = NULL;

    /* idmap  */
    nss_trans.name_to_uid    = name_to_uid;
    nss_trans.name_to_gid    = name_to_gid;
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

int name_to_uid(char *name, uid_t *uid)
{
    int muid = idmap_get_uid(name);
    if( muid < 0 ) return(-ENOENT);
    *uid = muid;
    return(0);
}

/* -------------------------------------------------------------------------- */

int name_to_gid(char *name, uid_t *gid)
{
    int mgid= idmap_get_gid(name);
    if( mgid < 0 ) return(-ENOENT);
    *gid = mgid;
    return(0);
}

/* -------------------------------------------------------------------------- */

int uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
    struct passwd *p_pwd = getpwuid(uid);
    if( p_pwd == NULL ) return(-ENOENT);

    return( idmap_user_to_local_domain(p_pwd->pw_name,name,len) );
}

/* -------------------------------------------------------------------------- */

int gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
    struct group *p_grp = getgrgid(gid);
    if( p_grp == NULL )return(-ENOENT);

    return( idmap_group_to_local_domain(p_grp->gr_name,name,len) );
}

/* -------------------------------------------------------------------------- */

int princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex)
{
    int             muid;
    struct passwd*  p_pw;

    /* check allowed security contexts */
    if (strcmp(secname, "spkm3") == 0) return(-ENOENT);
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    /* get principal uid */
    muid = idmap_get_princ_uid(princ);
    if( muid < 0 ) return(-ENOENT);

    /* get user info */
    p_pw = getpwuid(muid);
    if( p_pw == NULL ) return(-ENOENT);
    *uid = p_pw->pw_uid;
    *gid = p_pw->pw_gid;

    return(0);
}

/* -------------------------------------------------------------------------- */

int gss_princ_to_grouplist(char *secname, char *princ, gid_t *groups,
                           int *ngroups, extra_mapping_params **ex)
{
    int             muid;
    struct passwd*  p_pw;

    /* check allowed security contexts */
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    /* get principal uid */
    muid = idmap_get_princ_uid(princ);
    if( muid < 0 ) return(-ENOENT);

    /* get user info */
    p_pw = getpwuid(muid);
    if( p_pw == NULL ) return(-ENOENT);

    /*  get groups */
    if (getgrouplist(p_pw->pw_name, p_pw->pw_gid, groups, ngroups) < 0) return(-ERANGE);

    return(0);
}

/* -------------------------------------------------------------------------- */

