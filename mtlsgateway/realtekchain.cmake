# Cross-compile environment for realtek mips
set(CMAKE_SYSTEM_NAME RealTek)
set(CMAKE_SYSTEM_PROCESSOR mips)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH  /opt/realtek/rtl819x/toolchain/rsdk-4.6.4-4181-EB-3.10-u0.9.33-m32-150324)

# which compilers to use for C and C++
set(CMAKE_C_COMPILER   ${CMAKE_FIND_ROOT_PATH}/bin/mips-linux-gcc)
set(CMAKE_CXX_COMPILER ${CMAKE_FIND_ROOT_PATH}/bin/mips-linux-g++)
set(CMAKE_LINKER       ${CMAKE_FIND_ROOT_PATH}/bin/mips-linux-ld)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)