FROM ubuntu:jammy

LABEL maintainer="sivakesava@cs.ucla.edu"

RUN apt-get update 

RUN apt-get install -y \
    automake \
    bison \
    dnsutils \
    flex \
    gcc \
    git \
    libevent-dev \
    libssl-dev \
    make \
    openssl \
    curl \
    ca-certificates \
    vim 

RUN curl -L https://github.com/NLnetLabs/nsd/archive/refs/heads/master.tar.gz \
    | tar -xz && \
    mv nsd-master nsd && \
    cd nsd && \
    simd_url=$(awk '/path = simdzone/{p=1} p && /url =/{print $3}' .gitmodules) && \
    simd_base=${simd_url%.git} && \
    (curl -fL "$simd_base/archive/refs/heads/main.tar.gz" | tar -xz) || \
    (curl -fL "$simd_base/archive/refs/heads/master.tar.gz" | tar -xz) && \
    simd_name=$(basename "$simd_base") && \
    if [ -d "${simd_name}-main" ]; then mv "${simd_name}-main" simdzone; else mv "${simd_name}-master" simdzone; fi && \
    if [ ! -f simdzone/Makefile ] && [ ! -f simdzone/Makefile.in ] && [ ! -f simdzone/configure.ac ]; then \
      rm -rf simdzone && \
      git clone --depth 1 "${simd_base}.git" simdzone; \
    fi

ARG latest=false

RUN if [ "$latest" = "false" ] ; then cd nsd && git reset --hard 4043a5ab7be7abaec969011e48e4d0d60a0056a6 ; fi

RUN cd nsd && \
    autoreconf -if && \
    ./configure --disable-dnstap && \
    make && \
    make install && \
    ldconfig

# Copy configuration files
COPY Nsd/nsd.conf /etc/nsd/
COPY db.campus.edu /etc/nsd/zones/

RUN nsd-control-setup

# Run eternal loop
CMD ["/bin/bash", "-c", "while :; do sleep 10; done"]
