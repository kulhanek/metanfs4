# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# tests ------------------------------------------------------------------------
SET(METANFS4_TESTS_SRC
    main.cpp
    )

ADD_EXECUTABLE(metanfs4-tests ${METANFS4_TESTS_SRC})

TARGET_LINK_LIBRARIES(metanfs4-tests
    idmap_metanfs4
    nss_metanfs4
    )

# ------------------------------------------------------------------------------
