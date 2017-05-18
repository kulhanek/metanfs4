# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

SET(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# nsswitch ---------------------------------------------------------------------
SET(METANFS4NSS_SRC
    metanfs4_nsswitch.c
    ../metanfs4/common.c
    )

ADD_LIBRARY(nss_metanfs4 SHARED ${METANFS4NSS_SRC})
SET_TARGET_PROPERTIES(nss_metanfs4 PROPERTIES
    OUTPUT_NAME nss_metanfs4
    CLEAN_DIRECT_OUTPUT 1
    VERSION "2")

TARGET_LINK_LIBRARIES(nss_metanfs4
    pthread
    )

INSTALL(TARGETS nss_metanfs4
        DESTINATION lib)

# ------------------------------------------------------------------------------
