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
#include <SmallString.hpp>
#include <FileName.hpp>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>

#include "common.h"
#include "MetaNFS4dOptions.hpp"

// -----------------------------------------------------------------------------

#define CONFIG  "/etc/metanfs4.conf"

// -----------------------------------------------------------------------------
// global data
int             BaseID          = 5000000;
int             TopNameID       = 0;
int             TopGroupID      = 0;
int             ServerSocket    = -1;
CSmallString    NOBODY;
CSmallString    NOGROUP;
int             NobodyID        = -1;
int             NogroupID       = -1;
CSmallString    CacheFileName;
CSmallString    GroupFileName;
CSmallString    LOCALDOMAIN;
bool            Verbose = false;

// data storages
std::map<std::string,int> NameToID;
std::map<int,std::string> IDToName;
std::map<std::string,int> GroupToID;
std::map<int,std::string> IDToGroup;
std::map<std::string, std::set<std::string> > GroupMembers;


// -----------------------------------------------------------------------------
// initialize server
bool init_server(int argc,char* argv[]);

// finalize server
void finalize_server(void);

// start server loop
void start_main_loop(void);

// signal handler
void catch_signals(int signo);

// -----------------------------------------------------------------------------

bool is_local(const std::string &name,std::string &lname);
void map_to_local_ifnecessary(std::string &name);

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
    syslog(LOG_INFO,"starting server");    
    
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
    
// load config -----------------------------------
    CPrmFile config;
    if( config.Read(CONFIG) == false ){
        syslog(LOG_INFO,"unable to parse the config file %s",CONFIG);
        return(false);
    }
    
    if( config.OpenSection("config") == false ){
        syslog(LOG_INFO,"unable to open the 'config' section in the configuration file %s",CONFIG);
        return(false);
    }
    
    if( config.GetStringByKey("local",LOCALDOMAIN) == false ){
        syslog(LOG_INFO,"unable to read the 'local' domain from the configuration file %s",CONFIG);
        return(false);
    }
    syslog(LOG_INFO,"local domain: %s",(const char*)LOCALDOMAIN);
    
    
    // optional setup
    NOBODY = "nobody";
    config.GetStringByKey("nobody",NOBODY);
    NOGROUP = "nogroup";
    config.GetStringByKey("nogroup",NOGROUP);
    config.GetIntegerByKey("base",BaseID);

    if( config.OpenSection("files") == true ){
        config.GetStringByKey("cache",CacheFileName);
        config.GetStringByKey("group",GroupFileName);
    }   
    
// load cache if present
    if( (CacheFileName != NULL) && (options.GetOptSkipCache() == false) ){ 
        
        syslog(LOG_INFO,"cache file: %s",(const char*)CacheFileName);        
        
        struct stat cstat;
        if( stat(CacheFileName,&cstat) != 0 ){
            syslog(LOG_INFO,"unable to stat the cache file %s",(const char*)CacheFileName);
            return(false);            
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
            int         nid = -1;
            fin >> type >> name >> nid;
            if( (!fin) && (type == 'n') ){
                NameToID[name] = nid;
                IDToName[nid] = name;  
                if( TopNameID < nid ){
                    TopNameID = nid;
                }
                num++;
            }
            if( (!fin) && (type == 'g') ){
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
    }

// load group if present
    if( GroupFileName != NULL ){ 
        
        syslog(LOG_INFO,"group file: %s",(const char*)GroupFileName);
        
        struct stat cstat;
        if( stat(GroupFileName,&cstat) != 0 ){
            syslog(LOG_INFO,"unable to stat the group file %s",(const char*)GroupFileName);
            return(false);            
        }
        if( (cstat.st_uid != 0) || (cstat.st_gid != 0) || ((cstat.st_mode & 0777) != 0644) ){
            syslog(LOG_INFO,"wrong access rights on the group file %s(%d:%d/%o) (root:root/0644 is required)",(const char*)GroupFileName,cstat.st_uid,cstat.st_gid,(cstat.st_mode & 0777));
            return(false);
        }
        
        std::ifstream fin;
        fin.open(GroupFileName);
        int unum = 0;
        int gnum = 0;        
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
                    }
                    std::vector<std::string> usrs;  
                    boost::split(usrs,strs[3],boost::is_any_of(","));                    
                    std::vector<std::string>::iterator it = usrs.begin();
                    std::vector<std::string>::iterator ie = usrs.end();
                    while( it != ie ){
                        std::string uname = *it;
                        if( uname.find("@") != std::string::npos ){
                            if( NameToID.count(uname) == 0 ){
                                TopNameID++;
                                NameToID[uname] = TopNameID;
                                IDToName[TopNameID] = uname;
                                GroupMembers[gname].insert(uname);
                                unum++;
                            }                            
                        }
                        it++;
                    }
                    
                }
            }
        }
        syslog(LOG_INFO,"group items (users/groups): %d/%d",unum,gnum);
        fin.close(); 
    }
    
// rest of the setup -----------------------------

    // get nobody and nogroup
    struct passwd* psw = getpwnam(NOBODY);
    if( psw ){
        NobodyID = psw->pw_uid;
        syslog(LOG_INFO,"%s id is %d",(const char*)NOBODY,NobodyID);
    }
    struct group* grp = getgrnam(NOGROUP);
    if( grp ){
        NogroupID = grp->gr_gid;
        syslog(LOG_INFO,"%s id is %d",(const char*)NOGROUP,NogroupID);
    }

    // create server socket
    ServerSocket = socket(AF_UNIX,SOCK_STREAM,0);
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
    snprintf(address.sun_path,UNIX_PATH_MAX,"%s",SERVERNAME);
    int addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

    if( bind(ServerSocket,(struct sockaddr *) &address,addrlen) != 0 ){
        syslog(LOG_ERR,"unable to bind socket to %s",SERVERNAME);
        return(false);
    }
    
    // change access permitions
    chmod(SERVERNAME,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );

    // start listennig
    if( listen(ServerSocket, 5) != 0 ) {
        syslog(LOG_ERR,"unable to listen on socket %s",SERVERNAME);
        return(false);
    }

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
        struct msghdr       msgh;
        struct iovec        iov[1];
        char                cbuf[CMSG_SPACE(sizeof(ucred))];
        struct ucred*       cred;
        struct SNFS4Message data;

        memset(&msgh,0,sizeof(msgh));
        memset(cbuf,0,sizeof(cbuf));
        memset(&data,0,sizeof(data));

        msgh.msg_name = NULL;
        msgh.msg_namelen = 0;

        msgh.msg_iov = iov;
        msgh.msg_iovlen = 1;

        iov[0].iov_base = &data;
        iov[0].iov_len = sizeof(data);

        msgh.msg_control = cbuf;
        msgh.msg_controllen = sizeof cbuf;

        // we want sender credentials
        int passcred=1;
        setsockopt(connsckt,SOL_SOCKET,SO_PASSCRED,(void *)&passcred,sizeof(passcred));

        // receive data --------------------------
        if( recvmsg(connsckt,&msgh,0) == -1 ){
            syslog(LOG_ERR,"unable to receive message");
        }
        
        if( Verbose ){
            syslog(LOG_INFO,"request: type(%d), id(%d), name(%s)",data.Type,data.ID,data.Name);
        }

        // process data --------------------------
        try{
            switch(data.Type){
                case MSG_IDMAP_NAME_TO_ID:{
                    // check if sender is root
                    bool authorized = false;
                    struct cmsghdr *cmsg=NULL;
                    cmsg=CMSG_FIRSTHDR(&msgh);
                    while( cmsg != NULL ){
                        if( cmsg->cmsg_type == SCM_CREDENTIALS ){
                            cred = (struct ucred*)CMSG_DATA(cmsg);
                            if( cred != NULL ){
                                if( cred->uid == 0 ){
                                    authorized = true;
                                }
                            }
                        }
                        cmsg = CMSG_NXTHDR(&msgh,cmsg);
                    }
                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        syslog(LOG_INFO,"unauthorized request");
                        break;
                    }
                    
                    // perform operation
                    int         id = NobodyID; 
                    std::string name(data.Name);
                    std::string lname;
                    
                    if( is_local(name,lname) ){
                        if( ! lname.empty() ){
                            struct passwd *p_pwd = getpwnam(lname.c_str());  // only LOCAL query!!!
                            if( p_pwd != NULL ){
                                id = p_pwd->pw_uid;
                            }
                        } 

                    } else {
                        // get id
                        id = NameToID[name];
                        if( id == 0 ){
                            // not registered - create new record
                            TopNameID++;
                            NameToID[name] = TopNameID;
                            IDToName[TopNameID] = name;
                            id = TopNameID;
                        }
                        id = id + BaseID;
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_NAME_TO_ID;
                    data.ID = id;
                }
                break;
                
                case MSG_IDMAP_ID_TO_NAME:{
                    // check if sender is root
                    bool authorized = false;
                    struct cmsghdr *cmsg=NULL;
                    cmsg=CMSG_FIRSTHDR(&msgh);
                    while( cmsg != NULL ){
                        if( cmsg->cmsg_type == SCM_CREDENTIALS ){
                            cred = (struct ucred*)CMSG_DATA(cmsg);
                            if( cred != NULL ){
                                if( cred->uid == 0 ){
                                    authorized = true;
                                }
                            }
                        }
                        cmsg = CMSG_NXTHDR(&msgh,cmsg);
                    }
                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        break;
                    }
                    
                    struct passwd *p_pwd = getpwuid(data.ID);
                    std::string name = std::string(NOBODY);
                    if( p_pwd != NULL ){
                        name = p_pwd->pw_name;
                        map_to_local_ifnecessary(name);                        
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_ID_TO_NAME;
                    strncpy(data.Name,name.c_str(),MAX_NAME);
                }
                break;                
                
         
                case MSG_IDMAP_GROUP_TO_ID:{
                    // check if sender is root
                    bool authorized = false;
                    struct cmsghdr *cmsg=NULL;
                    cmsg=CMSG_FIRSTHDR(&msgh);
                    while( cmsg != NULL ){
                        if( cmsg->cmsg_type == SCM_CREDENTIALS ){
                            cred = (struct ucred*)CMSG_DATA(cmsg);
                            if( cred != NULL ){
                                if( cred->uid == 0 ){
                                    authorized = true;
                                }
                            }
                        }
                        cmsg = CMSG_NXTHDR(&msgh,cmsg);
                    }
                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        break;
                    }
                    
                    // perform operation
                    int id = NogroupID; 
                    std::string name(data.Name);
                    std::string lname;
                    
                    if( is_local(name,lname) ){
                        if( ! lname.empty() ){
                            struct group *p_grp = getgrnam(lname.c_str()); // only LOCAL query!!!
                            if( p_grp != NULL ){
                                id = p_grp->gr_gid;
                            }
                        }
                    } else {
                        // get id
                        id = GroupToID[name];
                        if( id == 0 ){
                            // not registered - create new record
                            TopGroupID++;
                            GroupToID[name] = TopGroupID;
                            IDToGroup[TopGroupID] = name;
                            id = TopGroupID;
                        }
                        id = id + BaseID;
                    }

                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_GROUP_TO_ID;
                    data.ID = id;
                }
                break;
                
                case MSG_IDMAP_ID_TO_GROUP:{
                    // check if sender is root
                    bool authorized = false;
                    struct cmsghdr *cmsg=NULL;
                    cmsg=CMSG_FIRSTHDR(&msgh);
                    while( cmsg != NULL ){
                        if( cmsg->cmsg_type == SCM_CREDENTIALS ){
                            cred = (struct ucred*)CMSG_DATA(cmsg);
                            if( cred != NULL ){
                                if( cred->uid == 0 ){
                                    authorized = true;
                                }
                            }
                        }
                        cmsg = CMSG_NXTHDR(&msgh,cmsg);
                    }
                    if( authorized == false ){
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        break;
                    }
                    
                    struct group *p_grp = getgrgid(data.ID);
                    std::string name = std::string(NOGROUP);
                    if( p_grp != NULL ){
                        name = p_grp->gr_name;
                        map_to_local_ifnecessary(name);
                    }
                    
                    memset(&data,0,sizeof(data));
                    data.Type = MSG_IDMAP_ID_TO_GROUP;
                    strncpy(data.Name,name.c_str(),MAX_NAME);
                }
                break;                
              
                case MSG_ID_TO_NAME:{
                    if( data.ID == NobodyID ){
                        strncpy(data.Name,NOBODY,MAX_NAME);
                    } else {
                        // get relevant data
                        int id = data.ID - BaseID;
                        // prepare response
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        std::string name = IDToName[id];
                        if( ! name.empty() ) {
                            data.Type = MSG_ID_TO_NAME;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                        }
                    }
                }
                break;

                case MSG_NAME_TO_ID:{
                    // get relevant data
                    std::string name(data.Name);
                    // prepare response
                    memset(&data,0,sizeof(data));
                    data.Type = MSG_NAME_TO_ID;
                    if( name != "NOBODY" ){
                        int id = NameToID[name];
                        if( id > 0 ) {
                            data.ID = id + BaseID;
                        } else {
                            data.ID = -1;
                        }
                    } else {
                        data.ID = NobodyID;                        
                    }
                }
                break;

                case MSG_ID_TO_GROUP:{
                    if( data.ID == NogroupID ){
                        strncpy(data.Name,NOGROUP,MAX_NAME);
                    } else {
                        // get relevant data
                        int id = data.ID - BaseID;
                        // prepare response
                        memset(&data,0,sizeof(data));
                        data.Type = MSG_UNAUTHORIZED;
                        std::string name = IDToGroup[id];
                        if( ! name.empty() ) {
                            data.Type = MSG_ID_TO_GROUP;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                        }
                    }
                }
                break;

                case MSG_GROUP_TO_ID:{
                    // get relevant data
                    std::string name(data.Name);
                    // prepare response
                    memset(&data,0,sizeof(data));
                    data.Type = MSG_GROUP_TO_ID;
                    if( name != "NOGROUP" ){
                        int id = GroupToID[name];
                        if( id > 0 ) {
                            data.ID = id + BaseID;
                        } else {
                            data.ID = -1;
                        }
                    } else {
                        data.ID = NogroupID;
                    }
                }
                break;

                case MSG_ENUM_NAME:{
                    int id = data.ID;
                    memset(&data,0,sizeof(data));
                    data.Type = MSG_ENUM_NAME;
                    if( (id >= 1) && (id <= TopNameID) ){
                        data.ID = id;
                        std::string name = IDToName[id];
                        if( ! name.empty() ) {
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                        }
                    } else {
                        data.ID = -1;
                    }
                }
                break;

                case MSG_ENUM_GROUP:{
                    int id = data.ID;
                    memset(&data,0,sizeof(data));
                    data.Type = MSG_ENUM_GROUP;
                    if( (id >= 1) && (id <= TopGroupID) ){
                        data.ID = id;
                        std::string name = IDToGroup[id];
                        if( ! name.empty() ) {
                            strncpy(data.Name,name.c_str(),MAX_NAME);
                        }
                    } else {
                        data.ID = -1;
                    }
                }
                break;
                
                case MSG_GROUP_MEMBER:{
                    // get relevant data
                    std::string gname(data.Name);
                    std::map<std::string, std::set<std::string> >::iterator git = GroupMembers.find(gname);
                    if( git != GroupMembers.end() ){
                        std::set<std::string>::iterator uit = git->second.begin();
                        for(int i=0; i < data.ID; i++) uit++;
                        if( uit != git->second.end() ){
                            std::string name = *uit;
                            data.Type = MSG_GROUP_MEMBER;
                            strncpy(data.Name,name.c_str(),MAX_NAME);
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
            syslog(LOG_INFO,"response: type(%d), id(%d), name(%s)",data.Type,data.ID,data.Name);
        }        

        memset(&msgh,0,sizeof(msgh));

        msgh.msg_name = NULL;
        msgh.msg_namelen = 0;

        msgh.msg_iov = iov;
        msgh.msg_iovlen = 1;

        iov[0].iov_base = &data;
        iov[0].iov_len = sizeof(data);

        msgh.msg_control = NULL;
        msgh.msg_controllen = 0;

        // send response -------------------------
        if( sendmsg(connsckt,&msgh,0) == -1 ){
            syslog(LOG_ERR,"unable to send message");
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
    
    // write cache if necessary    
    if( CacheFileName == NULL ) return;
    
    CFileName dir = CFileName(CacheFileName).GetFileDirectory();
    mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    chmod(dir, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH );
    
    std::ofstream fout(CacheFileName);
    if( fout ){
        chmod(CacheFileName,S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
        
        std::map<std::string,int>::iterator it = NameToID.begin();
        std::map<std::string,int>::iterator ie = NameToID.end();
        while( it != ie ){
            fout << "n " << it->first << " " << it->second << std::endl;
            it++;
        } 
        
        it = GroupToID.begin();
        ie = GroupToID.end();
        while( it != ie ){
            fout << "g " << it->first << " " << it->second << std::endl;
            it++;
        }
        fout.close();
    }
}

// -----------------------------------------------------------------------------

bool is_local(const std::string &name,std::string &lname)
{
    std::vector<std::string> bufs;
    boost::split(bufs,name,boost::is_any_of("@"));
    
    lname = name;
    if( bufs.size() <= 1 ) return(false);
    lname = bufs[0];
    return(true);
}

// -----------------------------------------------------------------------------

void map_to_local_ifnecessary(std::string &name)
{
    if( name.find("@") == std::string::npos ){
        name = name + std::string("@") + std::string(LOCALDOMAIN);
    }
}

// -----------------------------------------------------------------------------
