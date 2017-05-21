// =============================================================================
// MetaNFS4 - user/id mapper for NFS4 mounts with the krb5 security type 
// -----------------------------------------------------------------------------
//    Copyright (C) 2016 Petr Kulhanek, kulhanek@chemi.muni.cz
//
//     This program is free software; you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation; either version 2 of the License, or
//     (at your option) any later version.
//
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License along
//     with this program; if not, write to the Free Software Foundation, Inc.,
//     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
// =============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <map>
#include <vector>
#include <set>
#include <string>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <iostream>
#include <sys/stat.h>
#include <PrmFile.hpp>
#include <PrmUtils.hpp>
#include <SmallString.hpp>
#include <FileName.hpp>
#include <stddef.h>
#include "MetaNFS4Version.hpp"

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>

#include "common.h"
#include "MetaNFS4dOptions.hpp"

// -----------------------------------------------------------------------------

#define CONFIG  "/etc/metanfs4.conf"

// -----------------------------------------------------------------------------
// global data
unsigned int            BaseID          = 5000000;
uid_t                   TopUserID       = 0;
gid_t                   TopGroupID      = 0;
int                     ServerSocket    = -1;
bool                    Verbose = false;

// [setup]
int                     QueueLen        = 65535;
std::string             NoBody          = "nobody";
int                     NobodyID        = -1;
std::string             NoGroup         = "nogroup";
int                     NoGroupID       = -1;
std::string             PrimaryGroup    = "all@METANFS4";
int                     PrimaryGroupID  = -1;

// RootSquesh will not influence sec=sys mounts, which is desired behaviour, see
// http://redsymbol.net/linux-kernel-boot-parameters/
// nfs.nfs4_disable_idmapping and nfsd.nfs4_disable_idmapping

// [local]
CSmallString            LocalDomain;
CSmallString            PrincipalMapFileName;
std::set<std::string>   LocalRealms;
struct stat             LastPrincMapStat;

// [group]
CSmallString            GroupFileName;
std::set<std::string>   LocalDomains;
struct stat             LastGroupStat;
bool                    IgnoreIfNotExist = false;

// [cache]
CSmallString            CacheFileName;

// data storages
std::map<std::string,uid_t> UserToID;
std::map<uid_t,std::string> IDToUser;
std::map<std::string,gid_t> GroupToID;
std::map<gid_t,std::string> IDToGroup;

// principal mappings
std::map<std::string,std::string>               PrincipalMap;

// group members
std::map<std::string, std::set<std::string> >   GroupMembers;


// -----------------------------------------------------------------------------
// initialize server
bool init_server(int argc,char* argv[]);

// finalize server
void finalize_server(void);

// start server loop
void start_main_loop(void);

// signal handler
void catch_signals(int signo);

// load config and files
bool load_config(void);
bool load_cache(bool skip);
bool load_group(void);
bool reload_group(void);
bool load_principal_map(void);
bool reload_principal_map(void);

// -----------------------------------------------------------------------------

// test if name is from local domain
bool is_domain_local(const std::string &name,std::string &lname);

// map to local domain if necessary
void map_to_localdomain_ifnecessary(std::string &name);

// it returns local user name if principal is local
const std::string is_princ_local(const std::string &princ);

// conditional mapping of user to local account
const std::string can_user_be_local(const std::string &name);

// get or register user or group
int GetOrRegisterUser(const std::string& name);
int GetOrRegisterGroup(const std::string& name);

// generate group list
void generate_group_list(const std::string& gname,std::string& extra_data,size_t& len,gid_t& num);

// -----------------------------------------------------------------------------

int main(int argc,char* argv[])
{
    // init server
    if( init_server(argc,argv) == false ){
        finalize_server();
        return(1);
    }

    // process incomming requests
    start_main_loop();

    // finalize server
    finalize_server();

    return(0);
}

// -----------------------------------------------------------------------------

// initialize server
bool init_server(int argc,char* argv[])
{
    // open syslog
    openlog("metanfs4d",LOG_PID,LOG_DAEMON);
    syslog(LOG_INFO,"==== starting server ====");
    
// setup options ---------------------------------
    CMetaNFS4dOptions options;
    
    // encode program options
    int result = options.ParseCmdLine(argc,argv);

    // should we exit or was it error?
    if( result != SO_CONTINUE ){
        syslog(LOG_INFO,"unable to parse the command options or it is a test run");
        return(false);   
    }
    
    Verbose = options.GetOptVerbose();

    // handle signals
    signal(SIGINT, catch_signals);
    signal(SIGTERM, catch_signals);
    
// load configuration and data -------------------
    if( load_config() == false ) return(false);
    if( load_cache(options.GetOptSkipCache()) == false ) return(false);
    if( load_group() == false ) return(false);
    if( load_principal_map() == false ) return(false);
    
// rest of the setup -----------------------------
    NobodyID = GetOrRegisterUser(NoBody);
    syslog(LOG_INFO,"%s id is %d",NoBody.c_str(),NobodyID);
    NoGroupID = GetOrRegisterGroup(NoGroup);
    syslog(LOG_INFO,"%s id is %d",NoGroup.c_str(),NoGroupID);
    PrimaryGroupID = GetOrRegisterGroup(PrimaryGroup);
    syslog(LOG_INFO,"%s id is %d",PrimaryGroup.c_str(),PrimaryGroupID);

    // create server socket
    ServerSocket = socket(AF_UNIX,SOCK_SEQPACKET,0);
    if( ServerSocket < 0 ){
        syslog(LOG_ERR,"unable to create socket");
        return(false);
    }

    // assign name
    unlink(SERVERNAME);
    mkdir(SERVERPATH,S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    chmod(SERVERPATH,S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);    

    struct sockaddr_un address;
    memset(&address, 0, sizeof(struct sockaddr_un));

    address.sun_family = AF_UNIX;
    strncpy(address.sun_path,SERVERNAME,UNIX_PATH_MAX);
    socklen_t addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1;

    if( bind(ServerSocket,(struct sockaddr *) &address,addrlen) != 0 ){
        syslog(LOG_ERR,"unable to bind socket to %s",SERVERNAME);
        return(false);
    }
    
    // change access permitions
    chmod(SERVERNAME,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );

    // start listennig
    if( listen(ServerSocket, QueueLen) != 0 ) {
        syslog(LOG_ERR,"unable to listen on socket %s",SERVERNAME);
        return(false);
    }

    return(true);
}

// -----------------------------------------------------------------------------

bool load_config(void)
{
// load config -----------------------------------
    syslog(LOG_INFO,"loading config file: %s",CONFIG);
    syslog(LOG_INFO,"MetaNFS4d %s",METANFS4_VERSION);
    syslog(LOG_INFO,"-------------------------------------------------------------------------------");

    CPrmFile config;
    if( config.Read(CONFIG) == false ){
        syslog(LOG_INFO,"unable to parse the config file %s",CONFIG);
        return(false);
    }

    CSmallString tmp;

// [setup]
    syslog(LOG_INFO,"[setup]");

    if( config.OpenSection("setup") == true ){
        // all is optional setup
        int bi = BaseID;
        config.GetIntegerByKey("BaseID",bi);
        BaseID = bi;
        config.GetIntegerByKey("QueueLen",QueueLen);
        config.GetStringByKey("NoBody",NoBody);
        config.GetStringByKey("NoGroup",NoGroup);
        config.GetStringByKey("PrimaryGroup",PrimaryGroup);
    }

    syslog(LOG_INFO,"base ID (BaseID): %d",BaseID);
    syslog(LOG_INFO,"queue length (QueueLen): %d",QueueLen);
    syslog(LOG_INFO,"nobody (NoBody): %s",NoBody.c_str());
    syslog(LOG_INFO,"nogroup (NoGroup): %s",NoGroup.c_str());
    syslog(LOG_INFO,"primary group (PrimaryGroup): %s",PrimaryGroup.c_str());

// [local]
    syslog(LOG_INFO,"[local]");

    if( config.OpenSection("local") == false ){
        syslog(LOG_INFO,"unable to open the [local] section in the configuration file %s",CONFIG);
        return(false);
    }
    if( config.GetStringByKey("LocalDomain",LocalDomain) == false ){
        syslog(LOG_INFO,"unable to read the 'LocalDomain' domain from the configuration file %s",CONFIG);
        return(false);
    }
    syslog(LOG_INFO,"local domain (LocalDomain): %s",(const char*)LocalDomain);

    config.GetStringByKey("PrincipalMap",PrincipalMapFileName);
    if( PrincipalMapFileName != NULL ){
        syslog(LOG_INFO,"principal map (PrincipalMap): %s",(const char*)PrincipalMapFileName);
    } else {
        syslog(LOG_INFO,"principal map (PrincipalMap): -disabled-");
    }

    tmp = NULL;
    config.GetStringByKey("LocalRealms",tmp);
    if( tmp != NULL ){
        std::string stmp(tmp);
        boost::split(LocalRealms,stmp,boost::is_any_of(","),boost::token_compress_on);
    }
    if( LocalRealms.size() != 0 ) {
        syslog(LOG_INFO,"local realms (LocalRealms): %s",boost::join(LocalRealms,",").c_str());
    } else {
        syslog(LOG_INFO,"local realms (LocalRealms): -disabled-");
    }

// [group]
    syslog(LOG_INFO,"[group]");

    if( config.OpenSection("group") == true ){
        config.GetStringByKey("Name",GroupFileName);
        tmp = NULL;
        config.GetStringByKey("LocalDomains",tmp);
        if( tmp != NULL ){
            std::string stmp(tmp);
            boost::split(LocalDomains,stmp,boost::is_any_of(","),boost::token_compress_on);
        }
        config.GetLogicalByKey("IgnoreIfNotExist",IgnoreIfNotExist);
    }

    if( GroupFileName != NULL ){
        syslog(LOG_INFO,"group file name (Name): %s",(const char*)GroupFileName);
        syslog(LOG_INFO,"ignore if the group file does not exist (IgnoreIfNotExist): %s",(const char*)PrmFileOnOff(IgnoreIfNotExist));
    } else {
        syslog(LOG_INFO,"group file name (Name): -disabled-");
    }

    if( LocalDomains.size() != 0 ) {
        syslog(LOG_INFO,"local domains (LocalDomains): %s",boost::join(LocalDomains,",").c_str());
    } else {
        syslog(LOG_INFO,"local domains (LocalDomains): -disabled-");
    }

// [cache]
    syslog(LOG_INFO,"[cache]");

    if( config.OpenSection("cache") == true ){
        config.GetStringByKey("Name",CacheFileName);
    }

    syslog(LOG_INFO,"cache file name (Name): %s",(const char*)CacheFileName);

    syslog(LOG_INFO,"-------------------------------------------------------------------------------");

    // check if the whole configuration was read
    if( config.CountULines() > 0 ){
        syslog(LOG_INFO,"FATAL ERROR: the configuration file contains unprocessed items (%d) - check spelling",config.CountULines());
    }

    return(true);
}

// -----------------------------------------------------------------------------

bool load_cache(bool skip)
{
// load cache if present and allowed
    if( CacheFileName == NULL ) return(true);
    if( skip == true ) return(true);

    syslog(LOG_INFO,"cache file: %s",(const char*)CacheFileName);

    struct stat cstat;
    if( stat(CacheFileName,&cstat) != 0 ){
        syslog(LOG_INFO,"ignore cache - unable to stat the cache file %s",(const char*)CacheFileName);
        return(true);
    }

    if( (cstat.st_uid != 0) || (cstat.st_gid != 0) || ((cstat.st_mode & 0777) != 0644) ){
        syslog(LOG_INFO,"wrong access rights on the cache file %s(%d:%d/%o) (root:root/0644 is required)",(const char*)CacheFileName,cstat.st_uid,cstat.st_gid,(cstat.st_mode & 0777));
        return(false);
    }

    std::ifstream fin;
    fin.open(CacheFileName);
    int num = 0;
    while( fin ){
        char        type = '-';
        std::string name;
        unsigned int nid = 0;
        fin >> type >> name >> nid;
        if( (fin) && (type == 'n') && (nid > 0) ){
            UserToID[name] = nid;
            IDToUser[nid] = name;
            if( TopUserID < nid ){
                TopUserID = nid;
            }
            num++;
        }
        if( (fin) && (type == 'g') && (nid > 0) ){
            GroupToID[name] = nid;
            IDToGroup[nid] = name;
            if( TopGroupID < nid ){
                TopGroupID = nid;
            }
            num++;
        }
    }
    syslog(LOG_INFO,"cached items: %d",num);
    fin.close();

    return(true);
}

// -----------------------------------------------------------------------------

void save_cache(void)
{
    // write cache if necessary
    if( CacheFileName == NULL ) return;

    syslog(LOG_INFO,"writing cache to %s",(const char*)CacheFileName);

    CFileName dir = CFileName(CacheFileName).GetFileDirectory();
    mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    chmod(dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH );

    std::ofstream fout(CacheFileName);
    int unum = 0;
    int gnum = 0;
    if( fout ){
        chmod(CacheFileName,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );

        std::map<std::string,uid_t>::iterator it = UserToID.begin();
        std::map<std::string,uid_t>::iterator ie = UserToID.end();
        while( it != ie ){
            fout << "n " << it->first << " " << it->second << std::endl;
            it++;
            unum++;
        }

        it = GroupToID.begin();
        ie = GroupToID.end();
        while( it != ie ){
            fout << "g " << it->first << " " << it->second << std::endl;
            it++;
            gnum++;
        }
        fout.close();
    }

    syslog(LOG_INFO,"number of cache records (users/groups): %d/%d",unum,gnum);
}

// -----------------------------------------------------------------------------

bool load_group(void)
{
// load group if present
    if( GroupFileName == NULL ) return(true);

    syslog(LOG_INFO,"group file: %s",(const char*)GroupFileName);

    memset(&LastGroupStat,0,sizeof(LastGroupStat));

    if( stat(GroupFileName,&LastGroupStat) != 0 ){
        syslog(LOG_INFO,"unable to stat the group file %s",(const char*)GroupFileName);
        if( IgnoreIfNotExist ) {
            syslog(LOG_INFO,"but ignored as requested (IgnoreIfNotExist = on)");
            return(true);
        }
        return(false);
    }
    if( (LastGroupStat.st_uid != 0) || (LastGroupStat.st_gid != 0) || ((LastGroupStat.st_mode & 0777) != 0644) ){
        syslog(LOG_INFO,"wrong access rights on the group file %s(%d:%d/%o) (root:root/0644 is required)",(const char*)GroupFileName,LastGroupStat.st_uid,LastGroupStat.st_gid,(LastGroupStat.st_mode & 0777));
        return(false);
    }

    // the file can be re-loaded over time make sure the list is empty
    GroupMembers.clear();

    std::ifstream fin;
    fin.open(GroupFileName);
    int unum = 0;
    int gnum = 0;
    int uinum = 0;
    int ulnum = 0;
    int ginum = 0;
    std::string line;
    while( getline(fin,line) ){
        std::vector<std::string> strs;
        boost::split(strs,line,boost::is_any_of(":"));
        if( strs.size() == 4 ){
            std::string gname = strs[0];
            if( gname.find("@") != std::string::npos ){
                if( GroupToID.count(gname) == 0 ){
                    TopGroupID++;
                    GroupToID[gname] = TopGroupID;
                    IDToGroup[TopGroupID] = gname;
                    gnum++;
                } else {
                    gnum++;
                    ginum++;
                }
                std::vector<std::string> usrs;
                boost::split(usrs,strs[3],boost::is_any_of(","));
                std::vector<std::string>::iterator it = usrs.begin();
                std::vector<std::string>::iterator ie = usrs.end();
                while( it != ie ){
                    std::string uname = *it;
                    if( uname.find("@") != std::string::npos ){
                        if( UserToID.count(uname) == 0 ){
                            TopUserID++;
                            UserToID[uname] = TopUserID;
                            IDToUser[TopUserID] = uname;
                            unum++;
                        } else {
                            unum++;
                            uinum++;
                        }
                        // add user with domain
                        GroupMembers[gname].insert(uname);
                        // and again if it can be mapped to local account and the mapping is allowed
                        // this is important for proper function of rsync with --chown or --groupmap
                        // RT#202411
                        // well after some discussion this will not be used as it can make mess on local FSs
                        std::string lname = can_user_be_local(uname);
                        if( ! lname.empty() ){
                            GroupMembers[gname].insert(lname);
                            ulnum++;
                        }
                    }
                    it++;
                }

            }
        }
    }
    syslog(LOG_INFO,"group items (users/groups): %d/%d",unum,gnum);
    syslog(LOG_INFO,"group items already read from cache (users/groups): %d/%d",uinum,ginum);
    syslog(LOG_INFO,"users mapped to local users: %d",ulnum);
    fin.close();

    return(true);
}

// -----------------------------------------------------------------------------

bool reload_group(void)
{
    if( GroupFileName == NULL ) return(true);

    struct stat my_stat;
    if( stat(GroupFileName,&my_stat) != 0 ){
        if( IgnoreIfNotExist ) return(true);
        syslog(LOG_INFO,"unable to stat the group file %s",(const char*)GroupFileName);
        return(false);
    }

    bool reload = false;
    reload |= my_stat.st_ino != LastGroupStat.st_ino;
    reload |= my_stat.st_size != LastGroupStat.st_size;
    reload |= my_stat.st_mtime != LastGroupStat.st_mtime;

    // reload the group if the file was modified
    if( reload == true )  return(load_group());
    return(true);
}

// -----------------------------------------------------------------------------

bool load_principal_map(void)
{
// load group if present
    if( PrincipalMapFileName == NULL ) return(true);

    syslog(LOG_INFO,"principalmap file: %s",(const char*)PrincipalMapFileName);

    memset(&LastPrincMapStat,0,sizeof(LastPrincMapStat));

    if( stat(PrincipalMapFileName,&LastPrincMapStat) != 0 ){
        syslog(LOG_INFO,"unable to stat the principalmap file %s",(const char*)PrincipalMapFileName);
        return(false);
    }
    if( (LastPrincMapStat.st_uid != 0) || (LastPrincMapStat.st_gid != 0) || ((LastPrincMapStat.st_mode & 0777) != 0644) ){
        syslog(LOG_INFO,"wrong access rights on the principalmap file %s(%d:%d/%o) (root:root/0644 is required)",(const char*)PrincipalMapFileName,LastPrincMapStat.st_uid,LastPrincMapStat.st_gid,(LastPrincMapStat.st_mode & 0777));
        return(false);
    }

    // the file can be re-loaded over time make sure the list is empty
    PrincipalMap.clear();

    std::ifstream fin;
    fin.open(PrincipalMapFileName);
    int unum = 0;
    std::string line;
    while( getline(fin,line) ){
        std::vector<std::string> strs;
        boost::split(strs,line,boost::is_any_of(":"));
        if( strs.size() == 2 ){
            if( strs[1] == "root" ) continue;
            PrincipalMap[strs[0]] = strs[1];
        }
    }

    syslog(LOG_INFO,"principalmap items (principal:local): %d",unum);
    fin.close();

    return(true);
}

// -----------------------------------------------------------------------------

bool reload_principal_map(void)
{
// load group if present
    if( PrincipalMapFileName == NULL ) return(true);

    struct stat my_stat;
    if( stat(PrincipalMapFileName,&my_stat) != 0 ){
        syslog(LOG_INFO,"unable to stat the principalmap file %s",(const char*)PrincipalMapFileName);
        return(false);
    }

    bool reload = false;
    reload |= my_stat.st_ino != LastPrincMapStat.st_ino;
    reload |= my_stat.st_size != LastPrincMapStat.st_size;
    reload |= my_stat.st_mtime != LastPrincMapStat.st_mtime;

    // reload the group if the file was modified
    if( reload == true )  return(load_principal_map());

    return(true);
}

// -----------------------------------------------------------------------------

void finalize_server(void)
{
    if( ServerSocket >= 0 ) close(ServerSocket);
    unlink(SERVERNAME);

    syslog(LOG_INFO,"closing server");

    // close syslog
    closelog();
}

// -----------------------------------------------------------------------------

void start_main_loop(void)
{
    int                 connsckt;
    struct sockaddr_un  address;
    socklen_t           address_length = sizeof(address);

    while( (connsckt = accept(ServerSocket,(struct sockaddr *)&address,&address_length)) > -1 ){
        // receive message
        struct SNFS4Message data;
        memset(&data,0,sizeof(data));

        // receive data --------------------------
        if( read(connsckt,&data,sizeof(data)) != sizeof(data) ){
            syslog(LOG_ERR,"unable to receive message");
        }
        
        if( Verbose ){
            syslog(LOG_INFO,"request: type(%d), ID(%d), Extra(%d), name(%s)",data.Type,data.ID.UID,data.Extra.UID,data.Name);
        }

        // supplementary data
        std::string extra_data;

        // process data --------------------------
        try{           
            switch(data.Type){

                case MSG_IDMAP_REG_NAME:{
                    // check if sender is root
                    bool authorized = false;
                    struct ucred cred;
                    socklen_t credlen = sizeof(cred);
                    if( getsockopt(connsckt,SOL_SOCKET,SO_PEERCRED,&cred,&credlen) == 0 ){
                        if( cred.uid == 0 ){
                            authorized = true;
                         }
                    }

                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_INVALID;
                        syslog(LOG_INFO,"unauthorized request");
                        break;
                    }

                    // perform operation
                    uid_t   uid = 0;
                    std::string name(data.Name);
                    std::string lname;

                    if( ! is_domain_local(name,lname) ){
                        // get id
                        uid = UserToID[name];
                        if( uid == 0 ){
                            // not registered - create new record
                            TopUserID++;
                            UserToID[name] = TopUserID;
                            IDToUser[TopUserID] = name;
                            uid = TopUserID;
                        }
                        uid = uid + BaseID;
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_REG_NAME;
                    data.ID.UID = uid;
                    data.Extra.UID = NobodyID;
                    strncpy(data.Name,lname.c_str(),MAX_NAME);
                }
                break;

                case MSG_IDMAP_REG_GROUP:{
                    // check if sender is root
                    bool authorized = false;
                    struct ucred cred;
                    socklen_t credlen = sizeof(cred);
                    if( getsockopt(connsckt,SOL_SOCKET,SO_PEERCRED,&cred,&credlen) == 0 ){
                        if( cred.uid == 0 ){
                            authorized = true;
                         }
                    }
                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_INVALID;
                        syslog(LOG_INFO,"unauthorized request");
                        break;
                    }

                    // perform operation
                    gid_t gid = 0;
                    std::string name(data.Name);
                    std::string lname;

                    if( ! is_domain_local(name,lname) ){
                        // get id
                        gid = GroupToID[name];
                        if( gid == 0 ){
                            // not registered - create new record
                            TopGroupID++;
                            GroupToID[name] = TopGroupID;
                            IDToGroup[TopGroupID] = name;
                            gid = TopGroupID;
                        }
                        gid = gid + BaseID;
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_REG_GROUP;
                    data.ID.GID = gid;
                    data.Extra.GID = NoGroupID;
                    strncpy(data.Name,lname.c_str(),MAX_NAME);
                }
                break;

                case MSG_IDMAP_PRINC_TO_ID:{

                    reload_principal_map(); // reload map if necessary

                    std::string name(data.Name);
                    std::string lname;

                    if( PrincipalMap.count(name) == 1 ){
                        lname = PrincipalMap[name];
                    } else {
                        lname = is_princ_local(name);
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_PRINC_TO_ID;

                    if( (! lname.empty()) && (lname.find("@") == std::string::npos) ){
                        struct passwd *p_pwd = getpwnam(lname.c_str());  // only LOCAL query!!!
                        if( p_pwd != NULL ){
                            strncpy(data.Name,lname.c_str(),MAX_NAME);
                            data.ID.UID = p_pwd->pw_uid;
                            data.Extra.GID = p_pwd->pw_gid;
                        }
                    }
                    // root squash
                    if( (data.ID.UID == 0) || (data.Extra.GID == 0) ){
                        strncpy(data.Name,NoBody.c_str(),MAX_NAME);
                        data.ID.UID = NobodyID;
                        data.Extra.GID = NoGroupID;
                    }
                }
                break;

            case MSG_IDMAP_USER_TO_LOCAL_DOMAIN:{

                    std::string name(data.Name);

                    if( name == "root" ){
                        name = NoBody;
                    } else {
                        map_to_localdomain_ifnecessary(name);
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_USER_TO_LOCAL_DOMAIN;
                    strncpy(data.Name,name.c_str(),MAX_NAME);
                }
                break;

            case MSG_IDMAP_GROUP_TO_LOCAL_DOMAIN:{

                    std::string name(data.Name);

                    if( name == "root" ){
                        name = NoGroup;
                    } else {
                        map_to_localdomain_ifnecessary(name);
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_GROUP_TO_LOCAL_DOMAIN;
                    strncpy(data.Name,name.c_str(),MAX_NAME);
                }
                break;
                
                case MSG_ID_TO_NAME:{
                    uid_t uid = data.ID.UID;
                    memset(&data,0,sizeof(data));
                    if( uid > BaseID ){
                        std::string name = IDToUser[uid - BaseID];
                        if( ! name.empty() ) {
                            data.Type = MSG_ID_TO_NAME;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                            data.ID.UID = uid;
                            data.Extra.GID = PrimaryGroupID;
                        }
                    }
                }
                break;

                case MSG_NAME_TO_ID:{
                    std::string name(data.Name);
                    uid_t id = UserToID[name];
                    memset(&data,0,sizeof(data));
                    if( id > 0 ) {
                        id = id + BaseID;
                        data.Type = MSG_NAME_TO_ID;
                        strncpy(data.Name,name.c_str(),MAX_NAME);
                        data.ID.UID = id;
                        data.Extra.GID = PrimaryGroupID;
                    }
                }
                break;

                case MSG_ENUM_NAME:{
                    reload_group();
                    uid_t id = data.ID.UID;
                    memset(&data,0,sizeof(data));
                    if( (id >= 1) && (id <= TopUserID) ){
                        std::string name = IDToUser[id];
                        if( ! name.empty() ) {
                            data.Type = MSG_ENUM_NAME;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                            data.ID.UID = id+BaseID;
                            data.Extra.GID = PrimaryGroupID;
                        }
                    }
                }
                break;

                case MSG_ID_TO_GROUP:{
                    gid_t gid = data.ID.GID;
                    memset(&data,0,sizeof(data));
                    if( gid > BaseID ) {
                        std::string name = IDToGroup[gid-BaseID];
                        if( ! name.empty() ) {
                            data.Type = MSG_ID_TO_GROUP;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                            data.ID.GID = gid;
                            generate_group_list(name,extra_data,data.Len,data.Extra.GID);
                        }
                    }
                }
                break;

                case MSG_GROUP_TO_ID:{
                    std::string name(data.Name);
                    memset(&data,0,sizeof(data));
                    gid_t id = GroupToID[name];
                    if( id > 0 ) {
                        data.Type = MSG_GROUP_TO_ID;
                        strncpy(data.Name,name.c_str(),MAX_NAME);
                        data.ID.GID = id + BaseID;
                        generate_group_list(name,extra_data,data.Len,data.Extra.GID);
                    }
                }
                break;

                case MSG_ENUM_GROUP:{
                    reload_group();
                    gid_t id = data.ID.GID;
                    memset(&data,0,sizeof(data));
                    if(  (id >= 1) && (id <= TopGroupID) ) {
                        std::string name = IDToGroup[id];
                        if( ! name.empty() ) {
                            data.Type = MSG_ENUM_GROUP;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                            data.ID.GID = id + BaseID;
                            generate_group_list(name,extra_data,data.Len,data.Extra.GID);
                        }
                    }
                }
                break;
                
                default:
                    memset(&data,0,sizeof(data));
                break;
            }
        } catch(...){
            syslog(LOG_ERR,"exception raised");
            memset(&data,0,sizeof(data));
        }
        
        if( Verbose ){
            syslog(LOG_INFO,"response: type(%d), ID(%d), Extra(%d), name(%s)",data.Type,data.ID.UID,data.Extra.UID,data.Name);
        }

        // send response -------------------------
        if( write(connsckt,&data,sizeof(data)) != sizeof(data) ){
            syslog(LOG_ERR,"unable to send message");
        }
        if( data.Len > 0 ){
            if( Verbose ){
                syslog(LOG_INFO,"response: type(%d), extra data sent (%ld)",data.Type,data.Len);
            }
            if( (size_t)write(connsckt,extra_data.data(),extra_data.length()) != extra_data.length() ){
                syslog(LOG_ERR,"unable to send extra message");
            }
        }

        close(connsckt);
    }
}

// -----------------------------------------------------------------------------

void catch_signals(int signo)
{
    if( signo == SIGTERM ){
        syslog(LOG_INFO,"SIGTERM received - shutting down server");
    }
    if( signo == SIGINT ){
        syslog(LOG_INFO,"SIGINT received - shutting down server");
    }
    close(ServerSocket);
    ServerSocket = -1;
    
    save_cache();
}

// -----------------------------------------------------------------------------

bool is_domain_local(const std::string &name,std::string &lname)
{
    std::vector<std::string> bufs;
    boost::split(bufs,name,boost::is_any_of("@"));
    
    lname = name;
    if( bufs.size() <= 1 ) return(true);
    lname = bufs[0];
    if( (bufs.size() == 2) && (bufs[1] == std::string(LocalDomain)) ) return(true);
    return(false);
}

// -----------------------------------------------------------------------------

void map_to_localdomain_ifnecessary(std::string &name)
{
    if( name.find("@") == std::string::npos ){
        name = name + std::string("@") + std::string(LocalDomain);
    }
}

// -----------------------------------------------------------------------------

const std::string is_princ_local(const std::string &princ)
{
    std::vector<std::string> bufs;
    boost::split(bufs,princ,boost::is_any_of("@"));

    if( bufs.size() != 2 ) return(std::string()); // the princ has to contain realm

    if( LocalRealms.count(bufs[1]) == 0 ) return(std::string()); // realm is not allowed to be mapped to local user

    // return name
    return(bufs[0]);
}

// -----------------------------------------------------------------------------

const std::string can_user_be_local(const std::string &name)
{
    std::vector<std::string> bufs;
    boost::split(bufs,name,boost::is_any_of("@"));

    if( bufs.size() != 2 ) return(std::string()); // the name has to contain domain

    if( LocalDomains.count(bufs[1]) == 0 ) return(std::string()); // domain is not allowed to be mapped to local user

    // try to determine if the local user exist
    struct passwd* p_pw = getpwnam(bufs[0].c_str());
    if( p_pw == NULL ) return(std::string());

    return(bufs[0]);
}

// -----------------------------------------------------------------------------

int GetOrRegisterUser(const std::string& name)
{
    // try metanfs4 user first
    if( UserToID.count(name) == 1 ){
        return(UserToID[name]+BaseID);
    }
    // if it is not local account register new group
    if( name.find("@") != std::string::npos ){
        TopUserID++;
        UserToID[name] = TopUserID;
        IDToUser[TopUserID] = name;
        return(TopUserID+BaseID);
    }
    // try local account
    struct passwd * p_pw = getpwnam(name.c_str());
    if( p_pw == NULL ) return(-1);
    if( p_pw->pw_uid == 0 ) return(-1);
    return( p_pw->pw_uid );
}

// -----------------------------------------------------------------------------

int GetOrRegisterGroup(const std::string& name)
{
    // try metanfs4 group first
    if( GroupToID.count(name) == 1 ){
        return(GroupToID[name]+BaseID);
    }
    // if it is not local account register new group
    if( name.find("@") != std::string::npos ){
        TopGroupID++;
        GroupToID[name] = TopGroupID;
        IDToGroup[TopGroupID] = name;
        return(TopGroupID+BaseID);
    }
    // try local account
    struct group * p_gr = getgrnam(name.c_str());
    if( p_gr == NULL ) return(-1);
    if( p_gr->gr_gid == 0 ) return(-1);
    return( p_gr->gr_gid );
}

// -----------------------------------------------------------------------------

void generate_group_list(const std::string& gname,std::string& extra_data,size_t& len,gid_t& num)
{
    // generate list of members
    std::map<std::string, std::set<std::string> >::iterator git = GroupMembers.find(gname);
    if( git != GroupMembers.end() ){
        num = git->second.size(); // number of members
        std::set<std::string>::iterator it = git->second.begin();
        std::set<std::string>::iterator ie = git->second.end();
        std::stringstream sextra;
        while( it != ie ){
            std::string name(*it);
            sextra.write(name.c_str(),name.size()+1);
            it++;
        }
        extra_data = sextra.str();
        len = extra_data.length();
    }
}

// -----------------------------------------------------------------------------

