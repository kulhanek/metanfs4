#ifndef MetaNFS4dOptionsH
#define MetaNFS4dOptionsH
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

#include <SimpleOptions.hpp>

//------------------------------------------------------------------------------

class CMetaNFS4dOptions : public CSimpleOptions {
public:
    // constructor - tune option setup
    CMetaNFS4dOptions(void);

// program name and description -----------------------------------------------
    CSO_PROG_NAME_BEGIN
    "metanfs4d"
    CSO_PROG_NAME_END

    CSO_PROG_DESC_BEGIN
    "MetaNFS4d user/id mapper daemon.\n"
    "Configuration file (/etc/metanfs4.conf):\n" 
    "[config]\n"
    "local      domain  # name of the local domain which is mapped to the system users/ids (mandatory)\n"
    "base       number  # base ID for automatically created IDs (default: 500000)\n"
    "nobody     name    # name of nobody user (default: nobody)\n" 
    "nogroup    name    # name of nogroup group (default: nogroup)\n"
    "[files]\n"
    "cache filename # full pathname to the daemon cache (optional)\n"      
    "group filename # full pathname to the static NFS4 group definition (optional)\n"         
    CSO_PROG_DESC_END

    CSO_PROG_ARGS_SHORT_DESC_BEGIN
    ""
    CSO_PROG_ARGS_SHORT_DESC_END

    CSO_PROG_ARGS_LONG_DESC_BEGIN
    ""
    CSO_PROG_ARGS_LONG_DESC_END

    CSO_PROG_VERS_BEGIN
    "2.0"
    CSO_PROG_VERS_END

// list of all options and arguments ------------------------------------------
    CSO_LIST_BEGIN
    // arguments ----------------------------
    // options ------------------------------
    CSO_OPT(bool,SkipCache)    
    CSO_OPT(bool,Help)
    CSO_OPT(bool,Version)
    CSO_OPT(bool,Verbose)
    CSO_LIST_END

    CSO_MAP_BEGIN
// description of options -----------------------------------------------------
    //----------------------------------------------------------------------
    CSO_MAP_OPT(bool,                           /* option type */
                SkipCache,                        /* option name */
                false,                          /* default value */
                false,                          /* is option mandatory */
                's',                           /* short option name */
                "nocache",                      /* long option name */
                NULL,                           /* parametr name */
                "do not read the cache on the daemon startup")   /* option description */
    //----------------------------------------------------------------------
    CSO_MAP_OPT(bool,                           /* option type */
                Verbose,                        /* option name */
                false,                          /* default value */
                false,                          /* is option mandatory */
                'v',                           /* short option name */
                "verbose",                      /* long option name */
                NULL,                           /* parametr name */
                "increase output verbosity")   /* option description */
    //----------------------------------------------------------------------
    CSO_MAP_OPT(bool,                           /* option type */
                Version,                        /* option name */
                false,                          /* default value */
                false,                          /* is option mandatory */
                '\0',                           /* short option name */
                "version",                      /* long option name */
                NULL,                           /* parametr name */
                "output version information and exit")   /* option description */
    //----------------------------------------------------------------------
    CSO_MAP_OPT(bool,                           /* option type */
                Help,                        /* option name */
                false,                          /* default value */
                false,                          /* is option mandatory */
                'h',                           /* short option name */
                "help",                      /* long option name */
                NULL,                           /* parametr name */
                "display this help and exit")   /* option description */
    CSO_MAP_END

// final operation with options ------------------------------------------------
private:
    virtual int CheckOptions(void);
    virtual int FinalizeOptions(void);
    virtual int CheckArguments(void);
    bool    IsError;
};

//------------------------------------------------------------------------------

#endif
