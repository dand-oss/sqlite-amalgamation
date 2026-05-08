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

#------------------------------------------------------------------------------
# platform/compiler specific settings
if(CMAKE_SYSTEM_NAME MATCHES Linux)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)
    target_link_libraries(${SHARED_PROJECT_NAME} PUBLIC Threads::Threads ${CMAKE_DL_LIBS} m)
    set_target_properties(${SHARED_PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--no-undefined")

    # crypto platform/compiler specific settings
    target_link_libraries(${CRY_PROJECT_NAME} INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)
    target_link_libraries(${SHARED_CRY_PROJECT_NAME} PUBLIC Threads::Threads ${CMAKE_DL_LIBS} m)
    set_target_properties(${SHARED_CRY_PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--no-undefined")

endif()

#------------------------------------------------------------------------------
configure_file(sqlite3_config.h.in ${CMAKE_BINARY_DIR}/sqlite3_config.h)

install(TARGETS ${PROJECT_NAME} ${SHARED_PROJECT_NAME} EXPORT ${PROJECT_NAME}Config
    ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

# crypto
install(TARGETS ${CRY_PROJECT_NAME} ${SHARED_CRY_PROJECT_NAME} EXPORT ${CRY_PROJECT_NAME}Config
    ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

install(EXPORT  ${PROJECT_NAME}Config
    NAMESPACE   SQLite::
    DESTINATION cmake
    )

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
