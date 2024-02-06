# build environment -- feel free to adapt to your needs.

FROM alpine:edge as base

RUN apk --no-cache upgrade \
  && apk add --no-cache --initramfs-diskless-boot \
  python3 gdb musl-dbg \
  curl tar \
  build-base perf \
  clang lld compiler-rt

COPY ./harness/ /opt/
RUN ls -alR /opt/
RUN make -C /opt/

#### switch to snapchang container ####
FROM ghcr.io/awslabs/snapchange

# copy whole root filesystem from build environment to this container layer
# SNAPSHOT_INPUT is the location that the snapshotting script will create.
COPY --from=base / "$SNAPSHOT_INPUT"

# set the path to the target within the root filesystem of the build environment
ENV SNAPSHOT_ENTRYPOINT="/opt/mujs_harness"
ENV SNAPSHOT_GDB_MODE="detach"
