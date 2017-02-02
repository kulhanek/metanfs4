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

/* -----------------------------------------------------------------------------
// #############################################################################
// -------------------------------------------------------------------------- */

struct trans_func nss_trans;

/* -------------------------------------------------------------------------- */

struct trans_func *libnfsidmap_plugin_init()
{
    nss_trans.name           = "metanfs4";
    nss_trans.init           = NULL;
    nss_trans.princ_to_ids   = NULL;
    nss_trans.name_to_uid    = name_to_uid;
    nss_trans.name_to_gid    = name_to_gid;
    nss_trans.uid_to_name    = uid_to_name;
    nss_trans.gid_to_name    = gid_to_name;
    nss_trans.gss_princ_to_grouplist = NULL;

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
    struct passwd *p_pwd = getpwuid(uid);
    if( p_pwd != NULL ){
        if( idmap_to_local(p_pwd->pw_name,name,len) == 0 ) return(0);        
    }     
    return(-ENOENT);     
}

/* -------------------------------------------------------------------------- */

int gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
    struct group *p_grp = getgrgid(gid);
    if( p_grp != NULL ){
        if( idmap_to_local(p_grp->gr_name,name,len) == 0 ) return(0);
    }   
    return(-ENOENT);
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
