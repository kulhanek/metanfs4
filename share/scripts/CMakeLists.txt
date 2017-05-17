# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

INSTALL(FILES
            append-domain
       DESTINATION
            share/utils
        PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        )       
