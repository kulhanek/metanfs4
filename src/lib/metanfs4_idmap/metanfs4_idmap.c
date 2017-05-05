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
#include "idmap_internal.h"
#include "common.h"

/* -------------------------------------------------------------------------- */

int name_to_uid(char *name, uid_t *uid);
int name_to_gid(char *name, uid_t *gid);
int uid_to_name(uid_t uid, char *domain, char *name, size_t len);
int gid_to_name(gid_t gid, char *domain, char *name, size_t len);

int princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex);
int gss_princ_to_grouplist(char *secname, char *princ, gid_t *groups,
                           int *ngroups, extra_mapping_params **ex);

/* -----------------------------------------------------------------------------
// #############################################################################
// -------------------------------------------------------------------------- */

struct trans_func nss_trans;

/* -------------------------------------------------------------------------- */

struct trans_func *libnfsidmap_plugin_init()
{
    nss_trans.name           = "metanfs4";
    nss_trans.init           = NULL;

    // idmap
    nss_trans.name_to_uid    = name_to_uid;
    nss_trans.name_to_gid    = name_to_gid;
    nss_trans.uid_to_name    = uid_to_name;
    nss_trans.gid_to_name    = gid_to_name;

    // krb5
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
    if( muid <= 0 ) return(-ENOENT);
    *uid = muid;
    return(0);
}

/* -------------------------------------------------------------------------- */

int name_to_gid(char *name, uid_t *gid)
{
    int mgid= idmap_get_gid(name);
    if( mgid <= 0 ) return(-ENOENT);
    *gid = mgid;
    return(0);
}

/* -------------------------------------------------------------------------- */

int uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
    return(idmap_get_name(uid,name,len));        
}

/* -------------------------------------------------------------------------- */

int gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
    return(idmap_get_group(gid,name,len));
}

/* -------------------------------------------------------------------------- */

int princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex)
{
    // check allowed security contexts
    if (strcmp(secname, "spkm3") == 0) return(-ENOENT);
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    // get principal uid
    int muid = idmap_get_princ_uid(princ);
    if( muid <= 0 ) return(-ENOENT);

    // get user info
    struct passwd* p_pw = getpwuid(muid);
    if( p_pw == NULL ) return(-ENOENT);
    *uid = p_pw->pw_uid;
    *gid = p_pw->pw_gid;

    return(0);
}

/* -------------------------------------------------------------------------- */

int gss_princ_to_grouplist(char *secname, char *princ, gid_t *groups,
                           int *ngroups, extra_mapping_params **ex)
{
   // check allowed security contexts
    if (strcmp(secname, "krb5") != 0) return(-EINVAL);

    // get principal uid
    int muid = idmap_get_princ_uid(princ);
    if( muid <= 0 ) return(-ENOENT);

    // get user info
    struct passwd* p_pw = getpwuid(muid);
    if( p_pw == NULL ) return(-ENOENT);

    // get groups
    if (getgrouplist(p_pw->pw_name, p_pw->pw_gid, groups, ngroups) < 0) return(-ERANGE);

    return(0);
}

/* -----------------------------------------------------------------------------
// #############################################################################
// -------------------------------------------------------------------------- */

/*
int main(int argc,char* argv[])
{
  int uid,err;
  char* name;
  char buffer[1000];

  name = "root";
  err = name_to_uid(name,&uid);  
  printf("%s uid=%d (%d)\n",name,uid,err);
  name = "kulhanek";
  err = name_to_uid(name,&uid);
  printf("%s uid=%d (%d)\n",name,uid,err);
  name = "kulhanek@META";
  err = name_to_uid(name,&uid);
  printf("%s uid=%d (%d)\n",name,uid,err);
  name = "root@NCBR";
  err = name_to_uid(name,&uid);
  printf("%s uid=%d (%d)\n",name,uid,err);
  name = "kulhanek@NCBR";
  err = name_to_uid(name,&uid);
  printf("%s uid=%d (%d)\n",name,uid,err);

  name = "root";
  err = name_to_gid(name,&uid);
  printf("%s gid=%d (%d)\n",name,uid,err);


  uid = 0;
  err = uid_to_name(uid,NULL,buffer,1000);
  printf("%d name=%s (%d)\n",uid,buffer,err);

  uid = 1000;
  err = uid_to_name(uid,NULL,buffer,1000);
  printf("%d name=%s (%d)\n",uid,buffer,err);

  uid = 0;
  err = gid_to_name(uid,NULL,buffer,1000);
  printf("%d group=%s (%d)\n",uid,buffer,err);

  uid = 5000001;
  err = gid_to_name(uid,NULL,buffer,1000);
  printf("%d group=%s (%d)\n",uid,buffer,err);


  return(0);
} */
