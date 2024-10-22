FROM ubuntu:22.04

ENV DEBIAN_FRONTEND="noninteractive"
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    checkinstall \
    git \
    autoconf \
    automake \
    libtool-bin \
    libreadline-dev \
    libusb-1.0-0-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libzip-dev \
    zlib1g-dev \
    python3 \
    udev

RUN git clone https://github.com/libimobiledevice/libplist.git && \
    cd libplist && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libplist -rf

RUN git clone https://github.com/libimobiledevice/libtatsu.git && \
    cd libtatsu && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libtatsu -rf

RUN git clone https://github.com/libimobiledevice/libimobiledevice-glue.git && \
    cd libimobiledevice-glue && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libimobiledevice-glue -rf

RUN git clone https://github.com/libimobiledevice/libusbmuxd.git && \
    cd libusbmuxd && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libusbmuxd -rf

RUN git clone https://github.com/libimobiledevice/libimobiledevice.git && \
    cd libimobiledevice && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libimobiledevice -rf

RUN git clone https://github.com/libimobiledevice/libirecovery.git && \
    cd libirecovery && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm libirecovery -rf

RUN git clone https://github.com/libimobiledevice/usbmuxd.git  && \
    cd usbmuxd && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm usbmuxd -rf

RUN git clone https://github.com/libimobiledevice/idevicerestore.git && \
    cd idevicerestore && \
    ./autogen.sh && \
    make && \
    make install && \
    cd .. && \
    rm idevicerestore -rf

RUN ldconfig
WORKDIR /tmp
COPY idevicerestore.sh /usr/sbin/idevicerestore.sh
CMD idevicerestore.sh

