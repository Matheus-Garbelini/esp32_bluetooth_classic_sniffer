cmake_minimum_required(VERSION 3.5)
project(btstack LANGUAGES CXX C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
if(NOT COMPILER_SUPPORTS_CXX17)
    message(FATAL_ERROR "Compiler ${CC} does not support C++17")
endif()
set(CMAKE_CXX_FLAGS -fPIC)
set(CMAKE_C_FLAGS -fPIC)


# BTstack Root
set(BTSTACK_ROOT "${PROJECT_SOURCE_DIR}")
message("BTSTACK_ROOT: ${BTSTACK_ROOT}")

# BTstack include
include_directories(${BTSTACK_ROOT}/3rd-party/micro-ecc)
include_directories(${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/include)
include_directories(${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/include)
include_directories(${BTSTACK_ROOT}/3rd-party/md5)
include_directories(${BTSTACK_ROOT}/3rd-party/hxcmod-player)
include_directories(${BTSTACK_ROOT}/3rd-party/hxcmod-player/mod)
include_directories(${BTSTACK_ROOT}/3rd-party/lwip/core/src/include)
include_directories(${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server)
include_directories(${BTSTACK_ROOT}/3rd-party/rijndael)
include_directories(${BTSTACK_ROOT}/3rd-party/yxml)
include_directories(${BTSTACK_ROOT}/3rd-party/tinydir)
include_directories(${BTSTACK_ROOT}/chipset/bcm)
include_directories(${BTSTACK_ROOT}/chipset/cc256x)
include_directories(${BTSTACK_ROOT}/chipset/csr)
include_directories(${BTSTACK_ROOT}/chipset/em9301)
include_directories(${BTSTACK_ROOT}/src)
include_directories(${BTSTACK_ROOT}/platform/posix)
include_directories(${BTSTACK_ROOT}/platform/embedded)
include_directories(${BTSTACK_ROOT}/platform/lwip)
include_directories(${BTSTACK_ROOT}/platform/lwip/port)
include_directories(.)

# BTstack sources
file(GLOB SOURCES_SRC       "${BTSTACK_ROOT}/src/*.c" "${BTSTACK_ROOT}/example/sco_demo_util.c")
file(GLOB SOURCES_BLE       "${BTSTACK_ROOT}/src/ble/*.c")
file(GLOB SOURCES_GATT      "${BTSTACK_ROOT}/src/ble/gatt-service/*.c")
file(GLOB SOURCES_CLASSIC   "${BTSTACK_ROOT}/src/classic/*.c")
file(GLOB SOURCES_MESH      "${BTSTACK_ROOT}/src/mesh/*.c")
file(GLOB SOURCES_BLUEDROID "${BTSTACK_ROOT}/3rd-party/bluedroid/encoder/srce/*.c" "${BTSTACK_ROOT}/3rd-party/bluedroid/decoder/srce/*.c")
file(GLOB SOURCES_MD5       "${BTSTACK_ROOT}/3rd-party/md5/md5.c")
file(GLOB SOURCES_UECC      "${BTSTACK_ROOT}/3rd-party/micro-ecc/uECC.c")
file(GLOB SOURCES_YXML      "${BTSTACK_ROOT}/3rd-party/yxml/yxml.c")
file(GLOB SOURCES_HXCMOD    "${BTSTACK_ROOT}/3rd-party/hxcmod-player/*.c"  "${BTSTACK_ROOT}/3rd-party/hxcmod-player/mods/*.c")
file(GLOB SOURCES_RIJNDAEL  "${BTSTACK_ROOT}/3rd-party/rijndael/rijndael.c")

set(SOURCES_POSIX
    ${BTSTACK_ROOT}/platform/posix/btstack_audio_portaudio.c
    ${BTSTACK_ROOT}/platform/posix/btstack_tlv_posix.c
    ${BTSTACK_ROOT}/platform/posix/hci_dump_posix_fs.c
    ${BTSTACK_ROOT}/platform/posix/wav_util.c
)

set(SOURCES_CHIPSET
    ${BTSTACK_ROOT}/chipset/bcm/btstack_chipset_bcm.c
    ${BTSTACK_ROOT}/chipset/csr/btstack_chipset_csr.c
)

set(LWIP_CORE_SRC
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/def.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/inet_chksum.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/init.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ip.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/mem.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/memp.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/netif.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/pbuf.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp_in.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/tcp_out.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/timeouts.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/udp.c
)
set (LWIP_IPV4_SRC
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/acd.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/dhcp.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/etharp.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/icmp.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_addr.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/core/ipv4/ip4_frag.c
)
set (LWIP_NETIF_SRC
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/netif/ethernet.c
)
set (LWIP_HTTPD
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/altcp_proxyconnect.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/fs.c
        ${BTSTACK_ROOT}/3rd-party/lwip/core/src/apps/http/httpd.c
)
set (LWIP_DHCPD
        ${BTSTACK_ROOT}/3rd-party/lwip/dhcp-server/dhserver.c
)
set (LWIP_PORT
        ${BTSTACK_ROOT}/platform/lwip/port/sys_arch.c
        ${BTSTACK_ROOT}/platform/lwip/bnep_lwip.c
)

set (SOURCES_LWIP ${LWIP_CORE_SRC} ${LWIP_IPV4_SRC} ${LWIP_NETIF_SRC} ${LWIP_HTTPD} ${LWIP_DHCPD} ${LWIP_PORT})

file(GLOB SOURCES_BLE_OFF   "${BTSTACK_ROOT}/src/ble/le_device_db_memory.c")
list(REMOVE_ITEM SOURCES_BLE ${SOURCES_BLE_OFF})


# select POSIX vs Windows versions
IF (WIN32)
    message("Building for Windows using WinUSB")
    # set(SOURCES_HCI_USB ${BTSTACK_ROOT}/platform/windows/hci_transport_h2_winusb.c)
    set(SOURCES_STDIN   ${BTSTACK_ROOT}/platform/windows/btstack_stdin_windows.c)
    # link_libraries( winusb setupapi)
ELSE()
    # message("Building for POSIX using libusb")

    # add libusb
    # find_path(LIBUSB_INCLUDE_DIR NAMES libusb.h PATH_SUFFIXES "include" "libusb" "libusb-1.0")
    # find_library(LIBUSB_LIBRARY NAMES usb-1.0 PATH_SUFFIXES "lib" "lib32" "lib64" "dylib")
    # get_filename_component(LIBUSB_LIBRARY_PATH ${LIBUSB_LIBRARY} DIRECTORY)
    # include_directories( ${LIBUSB_INCLUDE_DIR} )
    # link_directories( ${LIBUSB_LIBRARY_PATH} )
    # link_libraries( usb-1.0 )

    # set(SOURCES_HCI_USB ${BTSTACK_ROOT}/platform/libusb/hci_transport_h2_libusb.c)
    set(SOURCES_STDIN   ${BTSTACK_ROOT}/platform/posix/btstack_stdin_posix.c)

    list(APPEND SOURCES_POSIX ${BTSTACK_ROOT}/platform/posix/btstack_network_posix.c)
    list(APPEND SOURCES_POSIX ${BTSTACK_ROOT}/platform/posix/btstack_uart_posix.c)
ENDIF()

set(SOURCES
        ${SOURCES_MD5}
        ${SOURCES_YXML}
        ${SOURCES_BLUEDROID}
        ${SOURCES_POSIX}
        ${SOURCES_RIJNDAEL}
        # ${SOURCES_HCI_USB}
        ${SOURCES_STDIN}
        ${SOURCES_SRC}
        ${SOURCES_BLE}
        ${SOURCES_GATT}
        ${SOURCES_MESH}
        ${SOURCES_CLASSIC}
        ${SOURCES_UECC}
        ${SOURCES_HXCMOD}
        ${SOURCES_CHIPSET}
)
list(SORT SOURCES)

# create libs
add_library(btstack-lib STATIC ${SOURCES} btstack_config.h)
add_library(btstack SHARED ${SOURCES} btstack_config.h)

# create targets for all examples
file(GLOB EXAMPLES_C    "${BTSTACK_ROOT}/example/*.c")
list(SORT EXAMPLES_C)
file(GLOB EXAMPLES_GATT "${BTSTACK_ROOT}/example/*.gatt")

# remove some
file(GLOB EXAMPLES_OFF  "${BTSTACK_ROOT}/example/panu_demo.c" "${BTSTACK_ROOT}/example/sco_demo_util.c" "${BTSTACK_ROOT}/example/ant_test.c" "${BTSTACK_ROOT}/example/avrcp_browsing_client.c")
list(REMOVE_ITEM EXAMPLES_C ${EXAMPLES_OFF})

# on Mac 10.14, adding lwip to libstack results in a yet not understood link error
# workaround: add lwip sources only to lwip_examples
set (LWIP_EXAMPLES pan_lwip_http_server)
 
export(TARGETS btstack
FILE ${PROJECT_BINARY_DIR}/btstack-targets.cmake)