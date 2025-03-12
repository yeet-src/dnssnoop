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