FROM debian:bookworm-slim

ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV LANGUAGE=C.UTF-8
ENV LC_CTYPE=C.UTF-8

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBCONF_NOWARNINGS=yes

RUN  apt-get update \
  && apt-get -y install --no-install-recommends wget ca-certificates \
  && mkdir -p -m 755 /etc/apt/keyrings \
  && wget -qO/etc/apt/keyrings/githubcli-archive-keyring.gpg https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
  && apt-get update \
  && apt-get -y install --no-install-recommends \
       apt-utils autoconf automake build-essential gh git \
       iproute2 make pkg-config libcap2-bin libsnappy-dev libtool ssh sudo \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -m -s /bin/bash -G sudo user \
  && echo "user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/user \
  && chmod 0440 /etc/sudoers.d/user