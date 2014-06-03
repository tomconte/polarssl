cmake_minimum_required(VERSION 2.6)

SET(CMAKE_SYSTEM_NAME Generic)

SET(CMAKE_C_COMPILER avr-gcc)
SET(CMAKE_CXX_COMPILER avr-g++)

SET(CSTANDARD "-std=gnu99")
SET(CDEBUG "-gstabs")
SET(CWARN "-Wall -Wstrict-prototypes")
SET(CTUNING "-funsigned-char -funsigned-bitfields -fpack-struct -fshort-enums")
SET(COPT "-Os")
SET(CINCS "-I${Candi_SOURCE_DIR}/libarduino")
SET(CMCU "-mmcu=atmega168")
SET(CDEFS "-DF_CPU=16000000")


SET(CFLAGS "${CMCU} ${CDEBUG} ${CDEFS} ${CINCS} ${COPT} ${CWARN} ${CSTANDARD} ${CEXTRA}")
SET(CXXFLAGS "${CMCU} ${CDEFS} ${CINCS} ${COPT}")

SET(CMAKE_C_FLAGS ${CFLAGS})
SET(CMAKE_CXX_FLAGS ${CXXFLAGS})

project(POLARSSL C)

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build: None Debug Release Coverage ASan Check CheckFull"
    FORCE)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
  if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_GNUCC)
  if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
  endif(CMAKE_COMPILER_IS_CLANG)
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

option(USE_PKCS11_HELPER_LIBRARY "Build PolarSSL with the pkcs11-helper library." OFF)

option(ENABLE_ZLIB_SUPPORT "Build PolarSSL with zlib library." OFF)

if(LIB_INSTALL_DIR)
else()
set(LIB_INSTALL_DIR lib)
endif()

include_directories(include/)

if(ENABLE_ZLIB_SUPPORT)
  find_package(ZLIB)

  if(ZLIB_FOUND)
    include_directories(ZLIB_INCLUDE_DIR)
  endif(ZLIB_FOUND)
endif(ENABLE_ZLIB_SUPPORT)

add_subdirectory(library)
add_subdirectory(include)

ADD_CUSTOM_TARGET(apidoc
                  COMMAND doxygen doxygen/polarssl.doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_TARGET(test-ref-config
    COMMAND tests/scripts/test-ref-configs.pl
    )

ADD_CUSTOM_TARGET(lcov
    COMMAND geninfo *.gcda
    COMMAND genhtml -o ../../../Coverage *.info
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/library/CMakeFiles/polarssl.dir
    )

ADD_CUSTOM_TARGET(memcheck
    COMMAND ctest -O memcheck.log -D ExperimentalMemCheck
    COMMAND tail -n1 memcheck.log | grep 'Memory checking results:' > /dev/null
    COMMAND rm -f memcheck.log
    )
