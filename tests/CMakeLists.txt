CMAKE_MINIMUM_REQUIRED(VERSION 3.5)

PROJECT(libmspdb-tests)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_EXECUTABLE(pdbdump pdbdump.cc)
TARGET_LINK_LIBRARIES(pdbdump mspdb)

ADD_EXECUTABLE(pdbfetch pdbfetch.cc)
TARGET_LINK_LIBRARIES(pdbfetch mspdb)

ADD_EXECUTABLE(pdbtypes pdbtypes.cc)
TARGET_LINK_LIBRARIES(pdbtypes mspdb)

ADD_EXECUTABLE(pdbtypetree pdbtypetree.cc)
TARGET_LINK_LIBRARIES(pdbtypetree mspdb)

ADD_EXECUTABLE(pdbwrapper pdbwrapper.cc)
TARGET_LINK_LIBRARIES(pdbwrapper mspdb)