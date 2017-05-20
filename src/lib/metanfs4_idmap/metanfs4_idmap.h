#ifndef METANFS4_IDMAP_H
#define METANFS4_IDMAP_H

#include <pwd.h>
#include <grp.h>

/* idmap API */

/* -------------------------------------------------------------------------- */

typedef struct _extra_mapping_params {
        void *content;
        int content_type;
        int content_len;
} extra_mapping_params;

/* -------------------------------------------------------------------------- */

struct trans_func {
        char *name;
        int (*init)(void);
        int (*princ_to_ids)(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex);
        int (*name_to_uid)(char *name, uid_t *uid);
        int (*name_to_gid)(char *name, gid_t *gid);
        int (*uid_to_name)(uid_t uid, char *domain, char *name, size_t len);
        int (*gid_to_name)(gid_t gid, char *domain, char *name, size_t len);
        int (*gss_princ_to_grouplist)(char *secname, char *princ, gid_t *groups,
                int *ngroups, extra_mapping_params **ex);
};

/* ------------ */

int idmap_get_uid(char* name,uid_t* uid);
int idmap_get_gid(char* name,gid_t* gid);

/* ------------ */

int uid_to_name(uid_t uid, char *domain, char *name, size_t len);
int gid_to_name(gid_t gid, char *domain, char *name, size_t len);


/* ------------ */

int princ_to_ids(char *secname, char *princ, uid_t *uid, gid_t *gid,
                extra_mapping_params **ex);
int gss_princ_to_grouplist(char *secname, char *princ, gid_t *groups,
                           int *ngroups, extra_mapping_params **ex);

/* ------------ */

int idmap_user_to_local_domain(const char* name,char* lname,int len);
int idmap_group_to_local_domain(const char* name,char* lname,int len);

#endif
