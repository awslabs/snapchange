###################################################
#### Ubuntu root FS
FROM ubuntu:jammy as base
RUN apt-get update -q \
  && apt-get install -q -y build-essential clang gdb python3 \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*
#### Alpine root FS
# FROM alpine:edge as base
# RUN apk --no-cache upgrade \
#   && apk --no-cache --initramfs-diskless-boot add \
#     build-base python3 gdb clang compiler-rt

#### build harness
COPY ./harness/ /root/
RUN cd /root/ && make clean && make

###################################################
FROM snapchange

COPY --from=base / "$SNAPSHOT_INPUT"

ENV SNAPSHOT_ENTRYPOINT=/root/example
ENV SNAPSHOT_ENTRYPOINT_CWD="/tmp/"
ENV SNAPSHOT_IMGTYPE=initramfs
ENV COVERAGE_BREAKPOINT_COMMAND=angr
ENV LIBFUZZER=1
