FROM alpine:edge as base

RUN apk add --no-cache --initramfs-diskless-boot python3 gdb curl tar build-base perf

COPY ./* /opt/
RUN cd /opt/ && make clean && make


FROM snapchange

COPY --from=base / /image/

ENV SNAPSHOT_ENTRYPOINT=/opt/example
ENV SNAPSHOT_ENTRYPOINT_CWD="/opt/"
