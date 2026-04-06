FROM ubuntu:bionic

LABEL maintainer="sivakesava@cs.ucla.edu"

RUN apt-get update 
RUN apt-get install -y \
    curl \
    openssl \
    libssl-dev \
    pkg-config \
    git \
    vim 

# Hickory drops privileges to 'nobody' by default; ensure it exists
RUN getent group nobody || groupadd -r nobody
RUN getent passwd nobody || useradd -r -g nobody -s /usr/sbin/nologin nobody

RUN  curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN git clone https://github.com/hickory-dns/hickory-dns.git trust-dns


RUN cd trust-dns && \
    /root/.cargo/bin/cargo build --release

COPY db.campus.edu trust-dns/tests/test-data/named_test_configs/
COPY Trustdns/config.toml trust-dns/tests/test-data/named_test_configs/

# Run eternal loop
CMD ["/bin/bash", "-c", "while :; do sleep 10; done"]
