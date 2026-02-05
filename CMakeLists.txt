cmake_minimum_required(VERSION 3.22)
project(UIdentity VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 12.1.0
)

FetchContent_Declare(
  server
  GIT_REPOSITORY https://github.com/Usub-development/webserver.git
  GIT_TAG main
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

FetchContent_Declare(
  ulog
  GIT_REPOSITORY https://github.com/Usub-development/ulog.git
  GIT_TAG main
  OVERRIDE_FIND_PACKAGE
)

FetchContent_Declare(
  picosha2
  GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
  GIT_TAG v1.0.1
)

# Don't rely on PicoSHA2 providing CMake targets; it doesn't.
FetchContent_GetProperties(picosha2)
if(NOT picosha2_POPULATED)
  FetchContent_Populate(picosha2)
endif()

add_library(picosha2 INTERFACE)
add_library(picosha2::picosha2 ALIAS picosha2)

# picosha2.h lives at repo root
target_include_directories(picosha2 INTERFACE "${picosha2_SOURCE_DIR}")

FetchContent_Declare(uvent
  GIT_REPOSITORY https://github.com/Usub-development/uvent.git
  GIT_TAG main
  GIT_SHALLOW TRUE
  GIT_PROGRESS TRUE
)

FetchContent_MakeAvailable(server glaze jwt-cpp ulog uvent fmt)

find_package(OpenSSL REQUIRED)

# set(KEYCLOAK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/keycloak_pkce")

# file(GLOB_RECURSE KEYCLOAK_SOURCES CONFIGURE_DEPENDS
#   "${KEYCLOAK_DIR}/lib/src/*.cpp"
#   "${KEYCLOAK_DIR}/lib/src/**/*.cpp"
# )

# # If this still ends up empty, the path is wrong / folder missing
# if(NOT KEYCLOAK_SOURCES)
#   message(FATAL_ERROR "No keycloak pkce sources found under: ${KEYCLOAK_DIR}/lib/src")
# endif()

# add_library(keycloak_pkce SHARED ${KEYCLOAK_SOURCES})
# add_library(KeycloakPKCE::Lib ALIAS keycloak_pkce)

# target_include_directories(keycloak_pkce
#   PUBLIC "${KEYCLOAK_DIR}/lib/include"
#   PRIVATE "${KEYCLOAK_DIR}/lib/src"
# )

# target_link_libraries(keycloak_pkce
#   PRIVATE
#   fmt::fmt
#   OpenSSL::SSL
#   OpenSSL::Crypto
#   picosha2::picosha2
# )

# target_compile_definitions(keycloak_pkce PRIVATE ASIO_STANDALONE)

file(GLOB_RECURSE UIDENTITY_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/new-include/*.hpp")
file(GLOB_RECURSE UIDENTITY_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

# ---- app ----
add_executable(UIdentity 
    UIDENTITY_SOURCES
)

target_include_directories(UIdentity 
PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(UIdentity PUBLIC
  usub::server
  glaze::glaze
  jwt-cpp::jwt-cpp
  usub::ulog
  picosha2::picosha2
  usub::uvent
  OpenSSL::SSL
  OpenSSL::Crypto
)
