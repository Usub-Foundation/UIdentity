cmake_minimum_required(VERSION 3.22)
project(UIdentity VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# FetchContent_Declare(
#   fmt
#   GIT_REPOSITORY https://github.com/fmtlib/fmt.git
#   GIT_TAG 12.1.0
# )

FetchContent_Declare(
  ulog
  GIT_REPOSITORY https://github.com/Usub-development/ulog.git
  GIT_TAG main
  OVERRIDE_FIND_PACKAGE
)

FetchContent_Declare(
  uredis
  GIT_REPOSITORY https://github.com/Usub-development/uredis.git
  GIT_TAG main
)

FetchContent_Declare(
  unet
  GIT_REPOSITORY https://github.com/Usub-development/unet.git
  GIT_TAG 3110c269abe12488a7f1a0c0cb77be9186c764e1
)

FetchContent_Declare(
  glaze
  GIT_REPOSITORY https://github.com/stephenberry/glaze.git
  GIT_TAG v7.0.1
)

FetchContent_Declare(
  jwt-cpp
  GIT_REPOSITORY https://github.com/StormLord07/jwt-cpp.git
  GIT_TAG master
)


FetchContent_Declare(uvent
  GIT_REPOSITORY https://github.com/Usub-development/uvent.git
  GIT_TAG main
  GIT_SHALLOW TRUE
  GIT_PROGRESS TRUE
)

set(UREDIS_LOGS ON CACHE BOOL "Enable uredis internal logging" FORCE)
set(UREDIS_BUILD_EXAMPLES OFF CACHE BOOL "Disable uredis examples in parent builds" FORCE)
set(UREDIS_BUILD_TESTS OFF CACHE BOOL "Disable uredis tests in parent builds" FORCE)

FetchContent_MakeAvailable(ulog uredis unet glaze jwt-cpp uvent)

find_package(OpenSSL REQUIRED)


file(GLOB_RECURSE UIDENTITY_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE UIDENTITY_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(UIdentity
  ${UIDENTITY_SOURCES}
  ${UIDENTITY_HEADERS}
)

target_include_directories(UIdentity
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/>
)

target_link_libraries(UIdentity PUBLIC
  usub::unet
  glaze::glaze
  jwt-cpp::jwt-cpp
  usub::ulog
  usub::uvent
  usub::uredis
  OpenSSL::SSL
  OpenSSL::Crypto
)

# enable_testing()

# add_executable(UIdentityTests
#   tests/keycloak_flow_tests.cpp
# )

# target_link_libraries(UIdentityTests PRIVATE
#   UIdentity
#   OpenSSL::SSL
#   OpenSSL::Crypto
# )

# add_test(NAME keycloak_flow_tests COMMAND UIdentityTests)
