FROM alpine:edge as base

RUN apk add --no-cache --initramfs-diskless-boot python3 gdb curl tar build-base perf

COPY harness/* /opt/
RUN cd /opt/ && make

FROM snapchange
COPY --from=base / "$SNAPSHOT_INPUT"

ENV SNAPSHOT_ENTRYPOINT=/opt/example1
