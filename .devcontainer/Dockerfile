FROM debian:bookworm-slim

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive
ENV DEBCONF_NOWARNINGS=yes
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV LANGUAGE=C.UTF-8
ENV LC_CTYPE=C.UTF-8

RUN apt-get update \
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

