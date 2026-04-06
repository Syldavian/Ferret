FROM ubuntu:jammy

LABEL maintainer="sivakesava@cs.ucla.edu"

RUN apt-get update 

RUN apt-get install -y \
    autoconf \
    automake \
    dnsutils \
    gcc \
    git \
    libcap-dev \
    libnghttp2-dev \
    liburcu-dev \
    libtool \
    libtool-bin \
    libuv1-dev \
    libssl-dev \
    make \
    meson \
    ninja-build \
    openssl \
    pkgconf \
    python3 \
    python3-pip \
    vim 

RUN git clone https://gitlab.isc.org/isc-projects/bind9.git

ARG latest=false

RUN if [ "$latest" = "false" ] ; then cd bind9 && git reset --hard dbcf683c1a57f49876e329fca183cb39d20ca3a4 ; fi

RUN cd bind9 && \
    if [ -f configure.ac ]; then \
        autoreconf -fi && \
        ./configure && \
        make && \
        make install; \
    else \
        python3 -m pip install --upgrade meson && \
        meson setup build && \
        ninja -C build && \
        ninja -C build install; \
    fi && \
    ldconfig -v

RUN cd /usr/local/etc && \
    rndc-confgen -a

# Copy configuration files
COPY Bind/named.conf /usr/local/etc/
COPY db.campus.edu /usr/local/etc/

# Run eternal loop
CMD ["/bin/bash", "-c", "while :; do sleep 10; done"]
