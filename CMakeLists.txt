cmake_minimum_required(VERSION 2.6)

SET(CMAKE_SYSTEM_NAME Generic)

# add the Arduino toolchain to your PATH, e.g.
# export PATH=$PATH:~/iot/arduino-1.5.6-r2/hardware/tools/g++_arm_none_eabi/bin

SET(CMAKE_C_COMPILER arm-none-eabi-gcc)
SET(CMAKE_CXX_COMPILER arm-none-eabi-g++)

SET(HOME ~/iot/arduino-1.5.6-r2)
SET(ADIR ${HOME}/hardware)
SET(SAM arduino/sam/)
SET(CMSIS arduino/sam/system/CMSIS/)
SET(LIBSAM arduino/sam/system/libsam)

SET(CSTANDARD "-g -Os -w -ffunction-sections -fdata-sections -nostdlib --param max-inline-insns-single=500 -mcpu=cortex-m3  -mthumb")
SET(CDEBUG "")
SET(CWARN "")
SET(CTUNING "")
SET(COPT "")
SET(CINCS "-I${ADIR}/${LIBSAM} -I${ADIR}/${CMSIS}/CMSIS/Include/ -I${ADIR}/${CMSIS}/Device/ATMEL/ -I${ADIR}/${SAM}/cores/arduino -I${ADIR}/${SAM}/variants/arduino_due_x")
SET(CMCU "")
SET(CDEFS "-Dprintf=iprintf -DF_CPU=84000000L -DARDUINO=152 -D__SAM3X8E__ -DUSB_PID=0x003e -DUSB_VID=0x2341 -DUSBCON")

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
