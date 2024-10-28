FROM debian:bookworm-slim

ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV LANGUAGE=C.UTF-8
ENV LC_CTYPE=C.UTF-8

RUN env \
    DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NOWARNINGS=yes \
    bash -c 'apt-get update \
          && apt-get -y install --no-install-recommends \
               apt-utils \
               autoconf \
               automake \
               build-essential \
               ca-certificates \
               git \
               iproute2 \
               make \
               pkg-config \
               libcap2-bin \
               libsnappy-dev \
               libtool \
               ssh \
               sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* ' 2>&1

RUN useradd -m -s /bin/bash -G sudo user; \
    echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/user; \
    chmod 0440 /etc/sudoers.d/user

