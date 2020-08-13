# CMakeLists.txt
#
# https://github.com/ConsenSys/ethereum-dissectors/blob/master/CMakeLists.txt
# https://github.com/theostoican/Basic-Protocol-for-Wireshark/blob/master/myprot/CMakeLists.txt
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(tezos 0 0 1 0)

set(DISSECTOR_SRC
    tezos.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(tezos epan)

target_link_libraries(tezos epan)
target_link_libraries(tezos tezos_rs)
target_link_libraries(tezos sodium)

install_plugin(tezos epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  tezos
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
