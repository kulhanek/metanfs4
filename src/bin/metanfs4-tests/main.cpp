#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

extern "C" {
#include <metanfs4_nsswitch.h>
#include <metanfs4_idmap.h>
}

// -----------------------------------------------------------------------------

void test_pwent(void)
{
    _nss_metanfs4_setpwent();

    struct passwd passwd;
    int           errnop;
    char*         buffer;
    size_t        buflen = 1024;
    NSS_STATUS    ret;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    do{
        ret = _nss_metanfs4_getpwent_r(&passwd,buffer,buflen,&errnop);
        if( ret == NSS_STATUS_TRYAGAIN ){
            if( errnop == ERANGE ){
                free(buffer);
                buflen = 2*buflen;
                buffer = (char*)malloc(buflen*sizeof(char));
                if( buffer == NULL ) return;
                continue;
            }
        }
        if( ret == NSS_STATUS_SUCCESS ){
            printf("%s\n",passwd.pw_name);
        }
    } while( (ret == NSS_STATUS_SUCCESS) || (ret == NSS_STATUS_TRYAGAIN) );

    free(buffer);
    _nss_metanfs4_endpwent();
}

// -----------------------------------------------------------------------------

void test_grent(void)
{
    _nss_metanfs4_setgrent();

    struct group  group;
    int           errnop;
    char*         buffer;
    size_t        buflen = 1024;
    NSS_STATUS    ret;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    do{
        ret = _nss_metanfs4_getgrent_r(&group,buffer,buflen,&errnop);
        if( ret == NSS_STATUS_TRYAGAIN ){
            if( errnop == ERANGE ){
                free(buffer);
                buflen = 2*buflen;
                buffer = (char*)malloc(buflen*sizeof(char));
                if( buffer == NULL ) return;
                continue;
            }
        }
        if( ret == NSS_STATUS_SUCCESS ){
            printf("%s\n",group.gr_name);
        }
    } while( (ret == NSS_STATUS_SUCCESS) || (ret == NSS_STATUS_TRYAGAIN) );

    free(buffer);
    _nss_metanfs4_endgrent();
}

// -----------------------------------------------------------------------------

void test_getpwnam(const char *name,size_t buflen)
{
    struct passwd passwd;
    int           errnop;
    char*         buffer;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    _nss_metanfs4_getpwnam_r (name,&passwd,buffer,buflen,&errnop);

    free(buffer);
}

// -----------------------------------------------------------------------------

void test_getpwuid(uid_t uid,size_t buflen)
{
    struct passwd passwd;
    int           errnop;
    char*         buffer;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    _nss_metanfs4_getpwuid_r (uid,&passwd,buffer,buflen,&errnop);

    free(buffer);
}

// -----------------------------------------------------------------------------

void test_getgrnam(const char *name,size_t buflen)
{
    struct group  group;
    int           errnop;
    char*         buffer;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    _nss_metanfs4_getgrnam_r (name,&group,buffer,buflen,&errnop);

    free(buffer);
}

// -----------------------------------------------------------------------------

void test_getgrgid(gid_t gid,size_t buflen)
{
    struct group  group;
    int           errnop;
    char*         buffer;

    buffer = (char*)malloc(buflen*sizeof(char));
    if( buffer == NULL ) return;

    _nss_metanfs4_getgrgid_r(gid,&group,buffer,buflen,&errnop);

    free(buffer);
}

// -----------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    test_pwent();
    test_grent();

    for(size_t buflen = 0; buflen < 30; buflen++){
        test_getpwnam("kulhanek@META",buflen);
        test_getpwuid(-1,buflen);
        test_getpwuid(0,buflen);
    }

    test_getpwnam(NULL,10);

    for(size_t buflen = 0; buflen < 10000; buflen++){
        test_getgrnam("kulhanek@META",buflen);
        test_getgrgid(-1,buflen);
        test_getgrgid(0,buflen);
    }

    test_getgrnam(NULL,10);
}

// -----------------------------------------------------------------------------
