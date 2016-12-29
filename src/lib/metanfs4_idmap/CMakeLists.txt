# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# idmap ---------------------------------------------------------------------
SET(METANFS4IDMAP_SRC
    metanfs4_idmap.c
    ../metanfs4/common.c
    )

ADD_LIBRARY(idmap_metanfs4 SHARED ${METANFS4IDMAP_SRC})
SET_TARGET_PROPERTIES(idmap_metanfs4 PROPERTIES
    OUTPUT_NAME idmap_metanfs4
    CLEAN_DIRECT_OUTPUT 1
    VERSION "2")

INSTALL(TARGETS idmap_metanfs4
        DESTINATION lib)

# ------------------------------------------------------------------------------
