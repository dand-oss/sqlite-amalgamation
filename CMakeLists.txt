cmake_minimum_required(VERSION 3.8)
project(SQLite3
    VERSION   3.31.1
    LANGUAGES C
    )

###############
# ASI default settings
list(APPEND CMAKE_MODULE_PATH "$ENV{ASV_CMAKE}")
include(asv_cmake_defaults)
asv_cmake_defaults( )
###############

include(GNUInstallDirs)

set(SQLITE3_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite3)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Release or Debug?" FORCE)
endif()

option(SQLITE_ENABLE_VXWORKS "Build only SQLite3cry for SCADAPack VxWorks" OFF)
set(SCADAPACK_CTOOLS "" CACHE PATH "SCADAPack CTools root for SQLITE_ENABLE_VXWORKS builds")
set(SQLITE_BUILD_HOST_TARGETS ON)
if(SQLITE_ENABLE_VXWORKS)
    set(SQLITE_BUILD_HOST_TARGETS OFF)
endif()

function(sqlite_configure_scadapack_vxworks target_name)
    if(NOT SCADAPACK_CTOOLS)
        message(FATAL_ERROR "Set SCADAPACK_CTOOLS when building SQLite3cry for VxWorks")
    endif()

    set(scadapack_ctools_target_dir "${SCADAPACK_CTOOLS}/Arm7/target")
    set(scadapack_telepace_dir "${SCADAPACK_CTOOLS}/Controller/TelePACE")

    target_include_directories(${target_name} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/compat/vxworks" # POSIX header shims for SQLite.
        "${scadapack_telepace_dir}"                 # SCADAPack application headers.
        "${scadapack_ctools_target_dir}/h"          # VxWorks target headers.
        "${scadapack_ctools_target_dir}/h/wrn/coreip"
        )
    target_compile_options(${target_name} PRIVATE
        # SCADAPack ARM ABI.
        -march=armv4
        -mapcs
        -mabi=apcs-gnu
        -mno-thumb-interwork
        -mlittle-endian

        # VxWorks compatibility shim for amalgamated SQLite.
        -include
        "${CMAKE_CURRENT_SOURCE_DIR}/compat/vxworks/sqlite3_vxworks_compat.h"
        -std=gnu89
        -Wno-implicit-function-declaration
        -Wno-builtin-declaration-mismatch
        )
    target_compile_definitions(${target_name} PRIVATE
        # SCADAPack/VxWorks platform and toolchain identity.
        SCADAPACK_VXWORKS_SQLITE=1
        ARMEL
        CPU=ARMARCH4
        TOOL_FAMILY=gnu
        TOOL=gnu
        _REENTRANT=1
        _VX_CPU=_VX_ARMARCH4
        _VX_TOOL_FAMILY=gnu
        _VX_TOOL=gnu
        OS_VXWORKS
        SQLITE_OS_UNIX=1

        # Explicit SCADAPack SQLite policy overrides. Keep these visible because
        # they are the first defines to revisit when changing firmware assumptions.
        SQLITE_ENABLE_LOCKING_STYLE=0
        SQLITE_DEFAULT_LOCKING_MODE=1
        SQLITE_THREAD_OVERRIDE_LOCK=0
        HAVE_FDATASYNC=1
        SQLITE_MAX_MMAP_SIZE=0
        SQLITE_TEMP_STORE=3
        SQLITE_THREADSAFE=0
        SQLITE_OMIT_LOAD_EXTENSION=1
        SQLITE_ENABLE_COLUMN_METADATA=1
        SQLITE_OMIT_COMPILEOPTION_DIAGS
        SQLITE_DEFAULT_CACHE_SIZE=32
        SQLITE_DEFAULT_PAGE_SIZE=8192
        SQLITE_DEFAULT_WAL_AUTOCHECKPOINT=64

        # SQLite core build identity.
        NDEBUG=1
        SQLITE_CORE
        )
endfunction()

#------------------------------------------------------------------------------

# SQLite3 as static library:
add_library(${PROJECT_NAME} STATIC ${SQLITE3_SOURCE_DIR}/sqlite3.c)
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME   sqlite3
    PUBLIC_HEADER ${SQLITE3_SOURCE_DIR}/sqlite3.h
    )
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${SQLITE3_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
    )
if(NOT SQLITE_BUILD_HOST_TARGETS)
    set_target_properties(${PROJECT_NAME} PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

#------------------------------------------------------------------------------

set(CRY_PROJECT_NAME ${PROJECT_NAME}cry)

# SQLite3 with Crypto as static library:
add_library(${CRY_PROJECT_NAME} STATIC ${SQLITE3_SOURCE_DIR}/sqlite3.c crypto_vfs.c)
set_target_properties(${CRY_PROJECT_NAME} PROPERTIES
    OUTPUT_NAME   sqlite3cry
    PUBLIC_HEADER ${SQLITE3_SOURCE_DIR}/sqlite3.h
    )
target_include_directories(${CRY_PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${SQLITE3_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
    )
target_compile_definitions(${CRY_PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:SQLITE_CRYVFS>
    )
#------------------------------------------------------------------------------
# DON'T REALLY NEED TO RECOMPILE....
if(SQLITE_BUILD_HOST_TARGETS)
    # SQLite3 as shared library:
    set(SHARED_PROJECT_NAME ${PROJECT_NAME}-shared)
    add_library(${SHARED_PROJECT_NAME} SHARED ${SQLITE3_SOURCE_DIR}/sqlite3.c)
    set_target_properties(${SHARED_PROJECT_NAME} PROPERTIES
        OUTPUT_NAME   sqlite3-shared
        PUBLIC_HEADER ${SQLITE3_SOURCE_DIR}/sqlite3.h
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
    target_include_directories(${SHARED_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${SQLITE3_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
        )

    #------------------------------------------------------------------------------
    # SQLite3 with Crypto as shared library:
    set(SHARED_CRY_PROJECT_NAME ${PROJECT_NAME}cry-shared)
    add_library(${SHARED_CRY_PROJECT_NAME} SHARED ${SQLITE3_SOURCE_DIR}/sqlite3.c crypto_vfs.c)
    set_target_properties(${SHARED_CRY_PROJECT_NAME} PROPERTIES
        OUTPUT_NAME   sqlite3cry-shared
        PUBLIC_HEADER ${SQLITE3_SOURCE_DIR}/sqlite3.h
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        )
    target_include_directories(${SHARED_CRY_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${SQLITE3_SOURCE_DIR}>
        $<INSTALL_INTERFACE:include>
        )
    target_compile_definitions(${SHARED_CRY_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:SQLITE_CRYVFS>
         )
endif()

#------------------------------------------------------------------------------
if(SQLITE_ENABLE_VXWORKS)
    sqlite_configure_scadapack_vxworks(${CRY_PROJECT_NAME})
endif()

#------------------------------------------------------------------------------
# platform/compiler specific settings
if(CMAKE_SYSTEM_NAME MATCHES Linux)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)

    # crypto platform/compiler specific settings
    target_link_libraries(${CRY_PROJECT_NAME} INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)

    if(SQLITE_BUILD_HOST_TARGETS)
        target_link_libraries(${SHARED_PROJECT_NAME} PUBLIC Threads::Threads ${CMAKE_DL_LIBS} m)
        set_target_properties(${SHARED_PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--no-undefined")
        target_link_libraries(${SHARED_CRY_PROJECT_NAME} PUBLIC Threads::Threads ${CMAKE_DL_LIBS} m)
        set_target_properties(${SHARED_CRY_PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--no-undefined")
    endif()

endif()

#------------------------------------------------------------------------------
configure_file(sqlite3_config.h.in ${CMAKE_BINARY_DIR}/sqlite3_config.h)

set(SQLITE3_INSTALL_TARGETS ${PROJECT_NAME})
set(SQLITE3_CRY_INSTALL_TARGETS ${CRY_PROJECT_NAME})

if(NOT SQLITE_BUILD_HOST_TARGETS)
    set(SQLITE3_INSTALL_TARGETS)
else()
    list(APPEND SQLITE3_INSTALL_TARGETS ${SHARED_PROJECT_NAME})
    list(APPEND SQLITE3_CRY_INSTALL_TARGETS ${SHARED_CRY_PROJECT_NAME})
endif()

if(SQLITE3_INSTALL_TARGETS)
    install(TARGETS ${SQLITE3_INSTALL_TARGETS} EXPORT ${PROJECT_NAME}Config
        ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )
endif()

# crypto
install(TARGETS ${SQLITE3_CRY_INSTALL_TARGETS} EXPORT ${CRY_PROJECT_NAME}Config
    ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

if(SQLITE3_INSTALL_TARGETS)
    install(EXPORT  ${PROJECT_NAME}Config
        NAMESPACE   SQLite::
        DESTINATION cmake
        )
endif()

# crypto
install(EXPORT  ${CRY_PROJECT_NAME}Config
    NAMESPACE   SQLite::
    DESTINATION cmake
    )

install(FILES
    ${CMAKE_BINARY_DIR}/sqlite3_config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

#------------------------------------------------------------------------------
# SQLite3 shell application:
option(BUILD_SHELL "build SQLite3 shell application" ON)
if(BUILD_SHELL)
    add_executable(shell_app ${SQLITE3_SOURCE_DIR}/shell.c)
    set_target_properties(shell_app PROPERTIES OUTPUT_NAME sqlite3)
    target_link_libraries(shell_app PRIVATE ${PROJECT_NAME})

# crypto shell
    add_executable(shell_app_cry ${SQLITE3_SOURCE_DIR}/shell.c)
    set_target_properties(shell_app_cry PROPERTIES OUTPUT_NAME sqlite3cry)
    target_link_libraries(shell_app_cry PRIVATE ${CRY_PROJECT_NAME})

    if(MSVC)
        option(BUILD_SHELL_STATIC "build shell by static c/c++ runtime" ON)
        foreach(flag CMAKE_C_FLAGS_RELEASE CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_DEBUG)
            if(BUILD_SHELL_STATIC)
                string(REGEX REPLACE "/MD" "/MT" ${flag} "${${flag}}")
            else()
                string(REGEX REPLACE "/MT" "/MD" ${flag} "${${flag}}")
            endif()
            set(${flag} "${${flag}}" CACHE STRING "msvc flags" FORCE)
        endforeach()
    endif()
    install(TARGETS shell_app
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )

    # install crypto
    install(TARGETS shell_app_cry
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
endif()
