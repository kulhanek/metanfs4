# ==============================================================================
# MetaNFS4 CMake File
# ==============================================================================

INCLUDE_DIRECTORIES(lib/metanfs4)
INCLUDE_DIRECTORIES(lib/metanfs4_nsswitch)
INCLUDE_DIRECTORIES(lib/metanfs4_idmap)

ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(bin)
