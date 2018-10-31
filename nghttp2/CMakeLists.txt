cmake_minimum_required(VERSION 3.0)
project(nghttp2 VERSION 1.33.90)

set(LT_CURRENT  31)
set(LT_REVISION 0)
set(LT_AGE      17)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Version)

math(EXPR LT_SOVERSION "${LT_CURRENT} - ${LT_AGE}")
set(LT_VERSION         "${LT_SOVERSION}.${LT_AGE}.${LT_REVISION}")
set(PACKAGE_VERSION    "${PROJECT_VERSION}")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

include_directories(${CMAKE_CURRENT_BINARY_DIR}/..)

include(GNUInstallDirs)
include(CheckIncludeFile)

check_include_file("arpa/inet.h"  HAVE_ARPA_INET_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)

add_definitions(-DHAVE_CONFIG_H)

configure_file("lib/includes/nghttp2/nghttp2ver.h.in" "lib/includes/nghttp2/nghttp2ver.h" @ONLY)

add_subdirectory(lib)
