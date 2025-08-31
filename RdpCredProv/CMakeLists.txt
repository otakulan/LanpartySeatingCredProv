
set(MODULE_NAME "RdpCredProv")
set(MODULE_PREFIX "RDPCREDPROV")

add_library(${MODULE_NAME} SHARED
	common.h
	Dll.cpp
	Dll.h
	guid.cpp
	guid.h
	helpers.cpp
	helpers.h
	RdpCredential.cpp
	RdpCredential.h
	RdpProvider.cpp
	RdpProvider.h
	resources.rc
	RdpCredProv.def)

windows_rc_generate_version_info(
	NAME "${MODULE_NAME}" TYPE "DLL"
	VERSION "${RDPCREDPROV_VERSION}"
	FILENAME "${MODULE_NAME}.dll"
	VENDOR "${RDPCREDPROV_VENDOR}"
	COPYRIGHT "${RDPCREDPROV_COPYRIGHT}"
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")

# Enable C++ exception handling and set C++17 standard
target_compile_options(RdpCredProv PRIVATE /EHsc)
set_target_properties(RdpCredProv PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

target_link_libraries(RdpCredProv secur32 shlwapi nlohmann_json::nlohmann_json)
