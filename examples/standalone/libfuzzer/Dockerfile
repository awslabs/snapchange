###################################################
FROM ubuntu:jammy as base

RUN apt-get update -q \
  && apt-get install -q -y build-essential clang gdb python3 \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*
  
COPY ./harness/ /root/
RUN cd /root/ && make clean && make

###################################################
FROM snapchange

COPY --from=base / "$SNAPSHOT_INPUT"

ENV SNAPSHOT_ENTRYPOINT=/root/example
ENV SNAPSHOT_ENTRYPOINT_CWD="/tmp/"
ENV SNAPSHOT_IMGTYPE=disk
ENV LIBFUZZER=1
