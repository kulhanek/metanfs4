# metanfs4
The MetaNFS4 package provides nfsidmap and nsswith services suitable for mounting of NFS4 storages with the krb5 security type. The package is able to properly show file/directory owners and groups in situation when NFS4 servers with different user and group namespaces are mounted to one client. This functionality is achieved by creating local user and group accounts in the form **name@DOMAIN**, where **name** is a remote (user/group) account name and **DOMAIN** is a remote server name (usually some short string). These acounts are then exhibited to the system and can be used, for example, in the chgrp command.

## Building Package
The procedure is decribed [here](https://github.com/kulhanek/metanfs4-build).

## Contents
The packages provides:
* daemon (bin/metanfs4d)
* nfsidmap *metanfs4* plugin (lib/libidmap_metanfs4.so.2)
* nsswitch *metanfs4* plugin (lib/libnss_metanfs4.so.2)

On Ubuntu (tested for 16.04), nfsidmap and nsswitch must be installed to proper locations. This can be achieved by creating symbolic links:
* ln -s $PREFIX/lib/libidmap_metanfs4.so.2 /lib/x86_64-linux-gnu/libnfsidmap/metanfs4.so
* ln -s $PREFIX/lib/libnss_metanfs4.so.2 /lib/x86_64-linux-gnu/libnss_metanfs4.so.2
Note that these links are created automatically by [metanfs-build](https://github.com/kulhanek/metanfs4-build).

## Configuration

### /etc/idmapd.conf
The suitable configuration is:
```bash
[General]
Domain = NCBR                 # it must be specified but it is ignored on clients, it determines namespace of accounts

[Mapping]
Nobody-User = nobody
Nobody-Group = nogroup

[Translation]
Method = metanfs4
```

### /etc/idmapd.conf
The suitable configuration for *passwd* and *group* databases is:
```bash
passwd:         compat metanfs4
group:          compat metanfs4
```bash

### /etc/metanfs4.conf
The file contains the main configuration for metanfs4.

####[setup]
|BaseID       | NUMBER  | base id for new users and groups (default: 5000000)
|QueueLen     | NUMBER  | length of queue for incomming requests (default: 65535)
|NoBody       | STRING  | name of nobody user (default: nobody)
|NoGroup      | STRING  | name of nogroup group (default: nogroup)
|PrimaryGroup | STRING  | primary group for all metanfs4 users (default: all@METANFS4)

####[local]
|LocalDomain  | STRING  | name of local domain, it has to be the same as in /etc/idmapd.conf
|PrincipalMap | NAME    | file name with principal to local user mapping, expected format is *principal:locuser* on each line
|LocalRealms  | LIST    | comma separated list of local realms for principal to local user mapping, *LocalRealms* has lower priority than *PrincipalMap*

####[group]
File          | NAME    | group file name, syntax is the same as /etc/group, only names with domains (both group and user) are taken into account, the provided group id is ignored and is either taken from the cache or generated automatically
LocalDomains  | LIST    | comma separated list of domains, which can be considerred equivalent to the local domain for user accounts, if users from these domains can be mapped to local users then these local users are added to groups as well

####[cache]
File          | NAME    | file name with the metanfs4 cache. the cache contains only group/id and user/id mapping but not user/group ralations

