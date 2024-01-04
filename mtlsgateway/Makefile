CC=/opt/realtek/rtl819x/toolchain/rsdk-4.6.7-4181-EB-2.6.30-0.9.30-m32u-140129/bin/mips-linux-gcc
GIT_VERSION:=${shell git describe --tags}

build:
		$(CC) -static \
				main.c serial.c util.c\
				-o tlsserialgw \
				-DVERSION=\"$(GIT_VERSION)\"
		md5sum stlsserialgw > md5sum


upload: build
		cat serialgateway | ssh root@192.168.1.86 "cat >/tuya/serialgateway"
