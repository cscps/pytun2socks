cmake_minimum_required(VERSION 3.12)
project(pytun2socks C)

find_package(PythonLibs REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})
link_libraries(${PYTHON_LIBRARIES})
add_definitions(-DPLATFORM_DARWIN=1)
#add_definitions(-DLWIP_DEBUG=1)
#add_definitions(-DLWIP_DBG_TYPES_ON=1)
add_compile_options("-g")

set(CMAKE_C_STANDARD 99)
set(PYTUN2SOCKS_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(PYTUN2SOCKS_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(LIB_LWIP_DIR ${PYTUN2SOCKS_LIB_DIR}/lwip/)
set(LWIP_DIR ${PYTUN2SOCKS_LIB_DIR}/lwip/src)
set(EXECUTABLE_OUTPUT_PATH /Users/cs/workspace/pytun2socks/pytun2socks)

set(LWIP_INCLUDES
        ${LIB_LWIP_DIR}/src/include
        ${LIB_LWIP_DIR}/custom
        ${LIB_LWIP_DIR}/src/core
        ${LIB_LWIP_DIR}/src/core/ipv4
        ${LIB_LWIP_DIR}/src/core/ipv6
        )
include_directories(${LWIP_INCLUDES})
#add_subdirectory(${LIB_LWIP_DIR})
#target_link_libraries(lwip)
#link_libraries(lwip)
set(PY_LWIP_SOURCES
        src/lwip_module.c
        src/ip4_addr.c
        src/ip_addr.c
        src/tcp_pcb.c)

set(LWIP_SOURCES
        ${LIB_LWIP_DIR}src/api/err.c
        ${LIB_LWIP_DIR}src/core/udp.c
        ${LIB_LWIP_DIR}src/core/memp.c
        ${LIB_LWIP_DIR}src/core/init.c
        ${LIB_LWIP_DIR}src/core/pbuf.c
        ${LIB_LWIP_DIR}src/core/tcp.c
        ${LIB_LWIP_DIR}src/core/tcp_out.c
        ${LIB_LWIP_DIR}src/core/sys.c
        ${LIB_LWIP_DIR}src/core/netif.c
        ${LIB_LWIP_DIR}src/core/def.c
        ${LIB_LWIP_DIR}src/core/mem.c
        ${LIB_LWIP_DIR}src/core/tcp_in.c
        ${LIB_LWIP_DIR}src/core/stats.c
        ${LIB_LWIP_DIR}src/core/ip.c
        ${LIB_LWIP_DIR}src/core/timeouts.c
        ${LIB_LWIP_DIR}src/core/inet_chksum.c
        ${LIB_LWIP_DIR}src/core/ipv4/icmp.c
        ${LIB_LWIP_DIR}src/core/ipv4/ip4.c
        ${LIB_LWIP_DIR}src/core/ipv4/ip4_addr.c
        ${LIB_LWIP_DIR}src/core/ipv4/ip4_frag.c
        ${LIB_LWIP_DIR}src/core/ipv6/ip6.c
        ${LIB_LWIP_DIR}src/core/ipv6/nd6.c
        ${LIB_LWIP_DIR}src/core/ipv6/icmp6.c
        ${LIB_LWIP_DIR}src/core/ipv6/ip6_addr.c
        ${LIB_LWIP_DIR}src/core/ipv6/ip6_frag.c
        ${LIB_LWIP_DIR}custom/sys.c src/pbuf.c src/pbuf.h src/netif.c src/netif.h)
add_executable(pytun2socks ${PY_LWIP_SOURCES} ${PYTUN2SOCKS_DIR}/test_embbed.c tuntap/tun.c tuntap/tun.h ${LWIP_SOURCES})
