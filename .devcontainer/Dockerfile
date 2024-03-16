FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update \
 && apt-get install -y curl vim

# make extra downloads early in image creation to keep it stable and cached
RUN mkdir -p /opt/realtek \
 && curl -L https://sourceforge.net/projects/rtl819x/files/rtl819x-SDK-v3.4.7.3-full-package.tar.gz | tar xvz -C /opt/realtek

RUN apt-get install -y git perl python3-full build-essential gcc-multilib gcc make cmake ncurses-term lib32z1 \
 && rm -rf /var/lib/apt/lists/*

# split to keep download step in separate layer
RUN cd /opt/realtek/rtl819x-SDK-v3.4.7.3-full-package \
 && tar -zxvf rtl819x.tar.gz -C /opt/realtek

RUN ln -s /opt/realtek/rtl819x/boards/rtl8196e/ /opt/realtek/rtl819x/target \
 && ln -s /opt/realtek/rtl819x/boards/rtl8196e/image/ /opt/realtek/rtl819x/image \
 && ln -s /opt/realtek/rtl819x/boards/rtl8196e/romfs/ /opt/realtek/rtl819x/romfs  \
 && ln -s /opt/realtek/rtl819x/boards/rtl8196e/tmpfs/ /opt/realtek/rtl819x/tmpfs
 # && cp Kconfig /opt/realtek/rtl819x/Kconfig \
 # && cp .config /opt/realtek/rtl819x/.config \
 # && make    


