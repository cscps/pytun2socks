from setuptools import setup, Extension
import sys

platform = sys.platform

LIB_LWIP_DIR = "./lib/lwip/"
LWIP_SOURCES = [
"src/api/err.c",

"src/core/udp.c",
"src/core/memp.c",
"src/core/init.c",
"src/core/pbuf.c",
"src/core/tcp.c",
"src/core/tcp_out.c",
"src/core/sys.c",
"src/core/netif.c",
"src/core/def.c",
"src/core/mem.c",
"src/core/tcp_in.c",
"src/core/stats.c",
"src/core/ip.c",
"src/core/timeouts.c",
"src/core/inet_chksum.c",
"src/core/ipv4/icmp.c",
"src/core/ipv4/ip4.c",
"src/core/ipv4/ip4_addr.c",
"src/core/ipv4/ip4_frag.c",
"src/core/ipv6/ip6.c",
"src/core/ipv6/nd6.c",
"src/core/ipv6/icmp6.c",
"src/core/ipv6/ip6_addr.c",
"src/core/ipv6/ip6_frag.c",
"custom/sys.c",
]
LWIP_INCLUDES = [f"{LIB_LWIP_DIR}/src/include",
f"{LIB_LWIP_DIR}/custom",
f"{LIB_LWIP_DIR}/src/core",
f"{LIB_LWIP_DIR}/src/core/ipv4",
f"{LIB_LWIP_DIR}/src/core/ipv6"]

setup(name='lwip',
      author='cs',
      author_email='cscs010010@gmail.com',
      maintainer='cs',
      maintainer_email='cscs010010@gmail.com',
      description='lwip wrapper for python',
      # long_description=open('README.rst').read(),
      version='0.0.1',
      ext_modules=[Extension('pylwip', ['lwip_module.c', *[LIB_LWIP_DIR+s for s in LWIP_SOURCES]],
                             include_dirs=LWIP_INCLUDES,
                             extra_compile_args=['-g'],
                             define_macros=[('PLATFORM_LINUX', str(int(platform=="linux"))),
                                            ('PLATFORM_DARWIN', str(int(platform=="darwin"))),
                                            ("LWIP_DEBUG", '1'),
                                            ("LWIP_DBG_TYPES_ON", '1'),
                                            ],)],

      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: POSIX :: Linux',
          'Programming Language :: C',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Networking'])
