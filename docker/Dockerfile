FROM ubuntu:20.04

# Install prereqs
RUN apt update && DEBIAN_FRONTEND=noninteractive TZ="America/Chicago" apt install -y \
  curl sudo tzdata git gcc g++ bc lcov libattr1 libattr1-dev libcap-ng0 libcap-ng-dev e2tools unzip

COPY fuzzer_template/qemu_snapshot /qemu_snapshot
COPY install_linux_qemu.sh /qemu_snapshot/install_linux_qemu.sh

WORKDIR /qemu_snapshot

# Init the linux and patched qemu to start a snapshot
RUN /qemu_snapshot/install_linux_qemu.sh

# Install r2 for fixing the libfuzzer snapshot
RUN git clone https://github.com/radareorg/radare2 && \
  radare2/sys/install.sh

# Copy the runner
COPY start.sh /qemu_snapshot/start.sh

# Copy the fuzzer src template
COPY src /qemu_snapshot/src

ENTRYPOINT ["/qemu_snapshot/start.sh"]
