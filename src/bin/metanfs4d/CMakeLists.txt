# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# daemon -----------------------------------------------------------------------
SET(METANFS4D_SRC
    MetaNFS4dOptions.cpp
    MetaNFS4d.cpp
    )

ADD_EXECUTABLE(metanfs4d ${METANFS4D_SRC})

TARGET_LINK_LIBRARIES(metanfs4d
    ${PRMFILE_CLIB_NAME}
    ${HIPOLY_LIB_NAME}
    )

# ------------------------------------------------------------------------------
