CC=/opt/realtek/rtl819x/toolchain/rsdk-4.6.4-4181-EB-3.10-u0.9.33-m32-150324/bin/mips-linux-gcc
CFLAGS="-std=c99 -O2
#GIT_VERSION:=${shell git describe --tags || echo "dev"}

mbedtls:
		CC=$(CC) $(CFLAGS) DESTDIR=/opt/mbedtls $(MAKE) -C mbedtls lib

build: mbedtls
		$(CC) -static \
				main.c serial.c util.c\
				-o tlsserialgw \
				-DVERSION=\"$(GIT_VERSION)\"
		md5sum tlsserialgw > md5sum


upload: build
		cat serialgateway | ssh root@192.168.1.86 "cat >/tuya/serialgateway"
