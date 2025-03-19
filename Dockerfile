FROM debian:12

RUN apt-get update && apt-get install -y \
  wget \
  bpftool \
  build-essential \
  libbpf-dev \
  git \
  zstd \
  lsb-release \
  software-properties-common \
  gnupg \
  && wget https://apt.llvm.org/llvm.sh \
  && chmod +x llvm.sh \
  && ./llvm.sh 19 all \
  && rm llvm.sh

ARG username=debian
ARG user_id=1000
ARG group_id=$user_id
ARG user_shell=/bin/bash

RUN groupadd --gid $group_id $username \
    && useradd --uid $user_id --gid $group_id -m $username -s $user_shell

USER $username
