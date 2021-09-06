cmake_minimum_required(VERSION 3.18)

project(
  esp32_bluetooth_classic_sniffer
  LANGUAGES CXX C
  VERSION 1.0)

set(CMAKE_BUILD_RPATH_USE_ORIGIN ON)
set(CMAKE_BUILD_RPATH $ORIGIN host_stack runtime/install/lib/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY host_stack)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY host_stack)

set(PYTHON3_URL
    "https://github.com/indygreg/python-build-standalone/releases/download/20210506/cpython-3.8.10-x86_64-unknown-linux-gnu-pgo+lto-20210506T0943.tar.zst"
)

if(NOT EXISTS ${PROJECT_SOURCE_DIR}/runtime/success)
  file(DOWNLOAD ${PYTHON3_URL} ${PROJECT_SOURCE_DIR}/runtime.tar.zst
       SHOW_PROGRESS)
  execute_process(
    COMMAND
      bash -c
      "tar -I zstd -xf runtime.tar.zst && rm runtime.tar.zst && cp -R python/* runtime && rm -rd python"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_VARIABLE PYTHON_ERROR)
  if(PYTHON_ERROR)
    message(FATAL_ERROR ${PYTHON_ERROR})
  endif(PYTHON_ERROR)
  # Install requirements from requirements.txt
  execute_process(
    COMMAND bash -c "./runtime/install/bin/python3 -m pip install -r ./requirements.txt"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_VARIABLE PYTHON_ERROR)
  if(PYTHON_ERROR)
    message(FATAL_ERROR ${PYTHON_ERROR})
  endif(PYTHON_ERROR)
  # Save success indication file
  execute_process(
    COMMAND bash -c "touch runtime/success"
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    ERROR_VARIABLE PYTHON_ERROR)
  if(PYTHON_ERROR)
    message(FATAL_ERROR ${PYTHON_ERROR})
  endif(PYTHON_ERROR)
endif()
set(PYTHON_EXECUTABLE ${PROJECT_SOURCE_DIR}/runtime/install/bin/python3)

# Bluetooth Stack
set(BTSTACK_ROOT ${PROJECT_SOURCE_DIR}/host_stack/bluekitchen/)
add_subdirectory(${BTSTACK_ROOT})
set(BT_INCLUDES
    ${BTSTACK_ROOT}/3rd-party/micro-ecc
    ${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/include
    ${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/include
    ${BTSTACK_ROOT}/3rd-party/md5
    ${BTSTACK_ROOT}/3rd-party/hxcmod-player
    ${BTSTACK_ROOT}/3rd-party/hxcmod-player/mod
    ${BTSTACK_ROOT}/3rd-party/lwip/core/src/include
    ${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server
    ${BTSTACK_ROOT}/3rd-party/rijndael
    ${BTSTACK_ROOT}/3rd-party/yxml
    ${BTSTACK_ROOT}/3rd-party/tinydir
    ${BTSTACK_ROOT}/chipset/bcm
    ${BTSTACK_ROOT}/chipset/csr
    ${BTSTACK_ROOT}/src
    ${BTSTACK_ROOT}/platform/posix
    ${BTSTACK_ROOT}/platform/embedded
    ${BTSTACK_ROOT}/platform/lwip
    ${BTSTACK_ROOT}/platform/lwip/port
    ${BTSTACK_ROOT})

# BT programs executable
set(BT_PROGRAMS ${PROJECT_SOURCE_DIR}/host_stack/spp_counter.c
                ${PROJECT_SOURCE_DIR}/host_stack/sdp_rfcomm_query.c)
foreach(BT_PROGRAM_FILE ${BT_PROGRAMS})
  # add main.cpp and run loop
  get_filename_component(BT_PROGRAM ${BT_PROGRAM_FILE} NAME_WE)
  message("BT Program: ${BT_PROGRAM_FILE}")
  list(APPEND BT_PROGRAM_FILE
       ${BTSTACK_ROOT}/platform/posix/btstack_run_loop_posix.c
       ${PROJECT_SOURCE_DIR}/host_stack/bt_stack.cpp)
  add_executable(${BT_PROGRAM} ${BT_PROGRAM_FILE})
  target_link_libraries(${BT_PROGRAM} btstack pthread)
  target_include_directories(${BT_PROGRAM} PRIVATE ${BT_INCLUDES})
endforeach()

message("Build RPath: ${CMAKE_BUILD_RPATH}")
