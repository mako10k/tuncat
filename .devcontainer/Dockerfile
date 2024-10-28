FROM debian:bookworm-slim

ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV LANGUAGE=C.UTF-8
ENV LC_CTYPE=C.UTF-8

RUN env \
    DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NOWARNINGS=yes \
    apt-get update \
    && apt-get -y install --no-install-recommends \
            apt-utils \
            autoconf \
            automake \
            build-essential \
            git \
            iproute2 \
            make \
            pkg-config \
            libcap2-bin \
            libsnappy-dev \
            libtool \
            ssh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
          2>&1

