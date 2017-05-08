# metanfs4
The MetaNFS4 package provides nfsidmap and nsswith services suitable for mounting of NFS4 storages with the krb5 security type. The package is able to properly show file/directory owners and groups in situation when NFS4 servers with different user and group namespaces are mounted to one client. This functionality is achieved by creating local user and group accounts in the form **name@DOMAIN**, where **name** is a remote (user/group) account name and **DOMAIN** is a remote server name (usually some short string). These acounts are then exhibited to the system and can be used, for example, in the chgrp command.

## Building Package
The procedure is decribed [here](https://github.com/kulhanek/metanfs4-build).

## Contents
The packages provides:
* daemon (bin/metanfs4d)
* nfsidmap *metanfs4* plugin (lib/libidmap_metanfs4.so.2)
* nsswitch *metanfs4* plugin (lib/libnss_metanfs4.so.2)

On Ubuntu (tested for 16.04), nfsidmap and nsswitch must be installed to proper locations. This can be achieved by the following symbolic links:
* ln -s $PREFIX/lib/libidmap_metanfs4.so.2 /lib/x86_64-linux-gnu/libnfsidmap/metanfs4.so
* ln -s $PREFIX/lib/libnss_metanfs4.so.2 /lib/x86_64-linux-gnu/libnss_metanfs4.so.2
Note that these links are created automatically by [metanfs-build](https://github.com/kulhanek/metanfs4-build).

## Configuration

