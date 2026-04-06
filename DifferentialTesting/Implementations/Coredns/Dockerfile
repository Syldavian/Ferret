FROM golang:1.24

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tar \
 && rm -rf /var/lib/apt/lists/*

ARG latest=false
ARG COREDNS_REF=master

RUN if [ "$latest" = "false" ] ; then ref=6edc8fe7f6c2f57844c8ee7f7f5deef71085ebe8 ; else ref="$COREDNS_REF" ; fi && \
    curl -L "https://github.com/coredns/coredns/archive/refs/heads/${ref}.tar.gz" \
      | tar -xz || \
    curl -L "https://github.com/coredns/coredns/archive/refs/tags/${ref}.tar.gz" \
      | tar -xz || \
    curl -L "https://github.com/coredns/coredns/archive/${ref}.tar.gz" \
      | tar -xz && \
    dir=$(ls -d coredns-* | head -n1) && \
    mv "$dir" coredns

RUN cd coredns && \
    make

COPY db.campus.edu /go/coredns
COPY Coredns/Corefile /go/coredns

WORKDIR /go/coredns
# Run eternal loop
CMD ["/bin/bash", "-c", "while :; do sleep 10; done"] 
