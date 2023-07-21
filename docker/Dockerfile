FROM ubuntu:20.04

# Install prereqs
ARG DEBIAN_FRONTEND=noninteractive 
ARG TZ="America/Chicago" 
RUN apt-get update -q \
  && apt-get install -y --no-install-recommends -q \
    build-essential \
    curl sudo tzdata git gcc g++ bc lcov libattr1 libattr1-dev libcap-ng0 libcap-ng-dev e2tools unzip \
    libglib2.0-dev libgcrypt20-dev zlib1g-dev autoconf automake libtool \
    bison flex libpixman-1-dev \
    clang make ninja-build debootstrap libelf-dev \
    libssl-dev pkg-config \
    radare2 \
    openjdk-17-jdk unzip wget \
    libguestfs-tools \
    lz4 \
    linux-image-generic \
    busybox-static \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /snapchange

COPY ./fuzzer_template ./fuzzer_template

COPY ./install ./install
RUN chmod +x ./install/*

ARG DEPTH="--depth=1"
ARG LINUX_VERSION=""

ARG KASAN=0
ENV KASAN="$KASAN"

ARG BUSYBOX_STATIC="/busybox.static"
ENV BUSYBOX_STATIC="$BUSYBOX_STATIC"

RUN ./install/qemu.sh \
  && ./install/ghidra.sh \
  && ./install/linux.sh \
  && ls -al /snapchange/ \
  && test -e /snapchange/vmlinux \
  && test -e /snapchange/linux.bzImage \
  && test -e /snapchange/vmlinux.kasan \
  && test -e /snapchange/linux.kasan.bzImage

COPY ./utils/* /snapchange/
RUN chmod +x *.sh && test -x go.sh

ARG SNAPSHOT_USER="root"
ENV SNAPSHOT_USER="$USER"

ARG SNAPSHOT_EXTRACT=""
ENV SNAPSHOT_EXTRACT="$SNAPSHOT_EXTRACT"

ARG SNAPSHOT_OUTPUT="/snapshot/"
ENV SNAPSHOT_OUTPUT="$SNAPSHOT_OUTPUT"

ARG SNAPSHOT_INPUT="/image/"
ENV SNAPSHOT_INPUT="$SNAPSHOT_INPUT"

ARG SNAPSHOT_ENTRYPOINT_ARGUMENTS=""
ENV SNAPSHOT_ENTRYPOINT_ARGUMENTS="$SNAPSHOT_ENTRYPOINT_ARGUMENTS"

ARG SNAPSHOT_ENTRYPOINT
ENV SNAPSHOT_ENTRYPOINT="$SNAPSHOT_ENTRYPOINT"

ARG SNAPSHOT_CHOWN_TO="1000"
ENV SNAPSHOT_CHOWN_TO="$SNAPSHOT_CHOWN_TO"

ARG TEMPLATE_OUT="/out/"
ENV TEMPLATE_OUT="$TEMPLATE_OUT"

ENV SNAPSHOT_CHECK_FOR_GDB=1

ENTRYPOINT ["/snapchange/go.sh"]
