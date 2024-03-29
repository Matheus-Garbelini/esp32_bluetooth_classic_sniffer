# CMakeLists.txt
#
# Wireshark - Network traffic analyzer By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)
include(UseMakePluginReg)

# Plugin name and version info (major minor micro extra)
set_module_info(h4bcm 1 1 0 0)

set(DISSECTOR_SRC packet-h4bcm.c packet-btbrlmp.c)

set(PLUGIN_FILES plugin.c ${DISSECTOR_SRC})

set_source_files_properties(${PLUGIN_FILES} PROPERTIES COMPILE_FLAGS
                                                       "${WERROR_COMMON_FLAGS}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c plugin ${DISSECTOR_SRC})

add_plugin_library(h4bcm epan)

target_link_libraries(h4bcm epan)

target_compile_options(h4bcm PRIVATE -w)

install_plugin(h4bcm epan)

file(
  GLOB DISSECTOR_HEADERS
  RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
  "*.h")
checkapi(
  NAME
  h4bcm
  SWITCHES
  -g
  abort
  -g
  termoutput
  -build
  SOURCES
  ${DISSECTOR_SRC}
  ${DISSECTOR_HEADERS})

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables: c-basic-offset: 8 tab-width: 8 indent-tabs-mode: t End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
