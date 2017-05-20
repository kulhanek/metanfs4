#ifndef METANFS4_NSSWITCH_H
#define METANFS4_NSSWITCH_H

#include <nss.h>

/* nsswitch API */

#define NSS_STATUS enum nss_status

/* ------------ */

NSS_STATUS
_nss_metanfs4_setpwent(void);

NSS_STATUS
_nss_metanfs4_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop);

NSS_STATUS
_nss_metanfs4_endpwent(void);

/* ------------ */

NSS_STATUS
_nss_metanfs4_setgrent(void);

NSS_STATUS
_nss_metanfs4_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop);

NSS_STATUS
_nss_metanfs4_endgrent(void);

/* ------------ */

NSS_STATUS
_nss_metanfs4_getpwnam_r(const char *name, struct passwd *result,
                    char *buffer, size_t buflen, int *errnop);

NSS_STATUS
_nss_metanfs4_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop);

/* ------------ */

NSS_STATUS
_nss_metanfs4_getgrnam_r(const char *name, struct group *result,
                    char *buffer, size_t buflen, int *errnop);

NSS_STATUS
_nss_metanfs4_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop);

/* ------------ */
NSS_STATUS
_nss_metanfs4_getpasswd(struct SNFS4Message* p_msg, struct passwd *result, char *buffer,
                     size_t buflen, int *errnop);
NSS_STATUS
_nss_metanfs4_getgroup(struct SNFS4Message* p_msg, struct group *result, char *buffer, size_t buflen, int *errnop);

#endif
