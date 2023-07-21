#!/usr/bin/env bash

# make sure env vars have sensible default if not set:

if [[ -z "$SNAPSHOT_INPUT" ]]; then
    DIR=/image/
else
  if [[ -d "$SNAPSHOT_INPUT" ]]; then
    DIR="$SNAPSHOT_INPUT"
  else
    DIR=/image/
  fi
fi
if [[ -z "$SNAPSHOT_OUTPUT" ]]; then
  OUTPUT=/snapshot/
else
  OUTPUT="$SNAPSHOT_OUTPUT"
fi
if [[ -z "$SNAPSHOT_IMGTYPE" ]]; then
    # IMGTYPE="disk"
    IMGTYPE="initramfs"
else
    IMGTYPE="$SNAPSHOT_IMGTYPE"
fi
if [[ -z "$SNAPSHOT_USER" ]]; then
    USER=root
else
    USER="$SNAPSHOT_USER"
fi
if [[ -z "$LIBFUZZER" ]]; then 
    LIBFUZZER=0
fi
if [[ -z "$SNAPSHOT_EXTRACT" ]]; then
  SNAPSHOT_EXTRACT=""
fi
if [[ -z "$SNAPSHOT_CHECK_FOR_GDB" ]]; then
  SNAPSHOT_CHECK_FOR_GDB=1
fi
if [[ -z "$SNAPSHOT_ENTRYPOINT_ARGUMENTS" ]]; then
    SNAPSHOT_ENTRYPOINT_ARGUMENTS=""
fi
if [[ -z "$SNAPSHOT_ENTRYPOINT_CWD" ]]; then
    SNAPSHOT_ENTRYPOINT_CWD=""
fi
if [[ -z "$SNAPCHANGE_DEV" ]]; then
    SNAPCHANGE_DEV=0
fi

source /snapchange/log.sh || { echo "Failed to source /snapchange/log.sh"; exit 1; }

RELEASE=harness

SYMBOL_FILE_PATHS=""
SYMBOL_FILE_PATHS="/usr/lib/debug/lib/ld-musl-x86_64.so.1.debug"

if [[ -z "$SNAPSHOT_ENTRYPOINT" ]]; then
    log_error "require setting a SNAPSHOT_ENTRYPOINT"
    exit 1
fi

set -eu -o pipefail
# set -x

if ! [[ -d "$SNAPSHOT_INPUT" ]]; then
  mkdir -p "$DIR" || true
  pushd "$dir" >/dev/null
  tar -xf "$SNAPSHOT_INPUT"
  popd >/dev/null
fi

log_msg "preparing harnes root filesystem for snapshot"

BIN="$DIR/$SNAPSHOT_ENTRYPOINT"

if ! [[ -e "$BIN" ]]; then
  log_error "harness root filesystem does not contain entrypoint $SNAPSHOT_ENTRYPOINT"
  exit 1
fi

cp "$BIN" "$OUTPUT/$(basename "$BIN").bin"
if ! [[ -z "$SNAPSHOT_EXTRACT" ]]; then
  mkdir -p "$OUTPUT/image"
  for file in $SNAPSHOT_EXTRACT; do
    dest="$OUTPUT/image/$file"
    mkdir -p "$(dirname "$dest")" || true
    cp -r "$DIR/$file" "$dest"
  done
fi

if [[ "$LIBFUZZER" -eq 1 ]]; then 

    if ! nm "$BIN" | grep LLVMFuzzerTestOneInput; then
        log_error "LLVMFuzzerTestOneInput not found in $BIN."
        exit 1
    fi
    
    # If LIBFUZZER, dump the first 16 bytes of LLVMFuzzerTestOneInput to restore
    # after taking the snapshot. These bytes are corrupted 
    r2 -q -c 'p8 16 @ sym.LLVMFuzzerTestOneInput' $BIN > /tmp/libfuzzer.bytes.bak
fi

 
if [[ $USER = 'root' ]]; then
    HOMEDIR=/root/
else
    HOMEDIR="/home/$USER"
fi

# Make the directory to hold the original binary to copy into the snapshot directory
mkdir -p "$DIR/$HOMEDIR"

RC_LOCAL="$DIR/etc/rc.local"

GDBCMDS="/snapchange/snapshot.gdbcmds"
GDBPY="/snapchange/gdbsnapshot.py"
mkdir -p "$(dirname "$DIR/$GDBCMDS")" || true
mkdir -p "$(dirname "$DIR/$GDBPY")" || true

# Remove previous snapshot script
rm "$RC_LOCAL" || true

# Init the rc.local script
cat > "$RC_LOCAL" <<EOF
#!/bin/sh -ex

export SNAPSHOT=1

echo "[+] snapshotting program: $SNAPSHOT_ENTRYPOINT $SNAPSHOT_ENTRYPOINT_ARGUMENTS"

EOF

DIR_HAS_GDB=0
GDB_PATH="$(find "$DIR" -name gdb -type f | head -n 1)"
if [[ -n "$GDB_PATH" ]]; then

  GDB_INSIDE="/${GDB_PATH#*$DIR}"
  DIR_HAS_GDB=1
  cat >> "$RC_LOCAL" <<EOF
export GDB=$GDB_INSIDE
if ! test -e "\$GDB"; then
    echo "[ERROR] cannot find gdb"
    echo "[ERROR] cannot find gdb"
    echo "[ERROR] cannot find gdb"
    echo "[ERROR] cannot find gdb"
    exit 1
fi
EOF
else
  DIR_HAS_GDB=0

  if [[ "$SNAPSHOT_CHECK_FOR_GDB" -eq 1 ]]; then
    log_error "no gdb found in the harness root filesystem!"
    exit 1
  else
    log_warning "no gdb found in the harness root filesystem! continuing anyway (hopefully gdb is on the PATH )"
    echo "export GDB=gdb" >> "$RC_LOCAL"
  fi
fi

if [[ -z "$SNAPSHOT_ENTRYPOINT_CWD" ]]; then
    echo "cd $HOMEDIR || true" >> "$RC_LOCAL"
else
    echo "cd $SNAPSHOT_ENTRYPOINT_CWD || true" >> "$RC_LOCAL"
fi


# If user is not root, run gdb under gdb in order to gain kernel symbols as root
if [ $USER != 'root' ]; then
    cat > "$RC_LOCAL" <<EOF
echo "[+] obtaining kernel symbols by running gdb under gdb"
\$GDB --command=$GDBCMDS --args \$GDB
mv /tmp/gdb.symbols /tmp/gdb.symbols.root
rm /tmp/gdb.modules
rm /tmp/gdb.vmmap

EOF
fi

# If user is not root, run gdb under the given user
if [ $USER != 'root' ]; then
    echo "su $USER -c '" >> $RC_LOCAL
fi

# Create the script to start on boot
echo -n "\$GDB --batch --command=$GDBCMDS --args "$SNAPSHOT_ENTRYPOINT" $SNAPSHOT_ENTRYPOINT_ARGUMENTS" >> $RC_LOCAL

# If user is not root, close the command executed
if [ $USER != 'root' ]; then
    echo "'" >> $RC_LOCAL
fi

# Add a newline
echo "" >> $RC_LOCAL

# Ensure the output files are actually written to the image
echo "sync" >> $RC_LOCAL

# Status check after GDB exits to see if the files are written
echo "ls -la" >> $RC_LOCAL


cat >> "$RC_LOCAL" <<EOF

echo "[+] Trying to mount 9pfs"
mount -t 9p -o trans=virtio snapchange_mnt /mnt/ -oversion=9p2000.L
echo "mounting 9pfs success? => \$?"

echo "[+] extracting logs to 9pfs"
cp -r /tmp/gdb.* /mnt/
if [ "\$PWD" != "/" ]; then
    cp -r . "/mnt/cwd"
fi
cat /proc/modules > /mnt/guestkernel.modules
cat /proc/kallsyms > /mnt/guestkernel.kallsyms

# Ensure the output files are actually written to the image
sync

echo "[+] ok. kthxbye."
# a trigger for the snapchange scripts that we are done with execution.
echo ""
echo "snapshot done"
echo ""
EOF


# Make the script executable and owned by root
chmod +x $RC_LOCAL
chown root:root $RC_LOCAL

# Add newline to thes script
echo "" >> $RC_LOCAL

# Copy in the gdbsnapshot.py
cp gdbsnapshot.py $DIR/$GDBPY
chmod a+r "$DIR/$GDBPY"

# Try to remove the old gdbcmds since we are writing a new one below
rm $DIR/$GDBCMDS || true

LOAD_SYMBOL_FILE=""
for try_load in $SYMBOL_FILE_PATHS; do
    if [[ -e "$DIR/$try_load" ]]; then
        LOAD_SYMBOL_FILE="add-symbol-file $try_load \n$LOAD_SYMBOL_FILE"
    fi
done

# Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
if [[ "$LIBFUZZER" -eq 1 ]]; then
    echo "LIBFUZZER SNAPSHOT DETECTED"
    echo "Taking a snapshot at LLVMFuzzerTestOneInput"
    cat > "$DIR/$GDBCMDS" <<EOF
$(printf "$LOAD_SYMBOL_FILE")
set pagination off
# Ignore leak detection. 
set environment ASAN_OPTIONS=detect_leaks=0

# Stop at the first chance in the target in order to enable the breakpoint on LLVMFuzzerTestOneInput
start
del *
x/16xb LLVMFuzzerTestOneInput

# Remove all coverage trace from libfuzzer since we are using breakpoint coverage in Snapchange
set {unsigned char}(__sanitizer_cov_trace_cmp1)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp2)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_cmp8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp1)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp2)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_const_cmp8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_div4)=0xc3
set {unsigned char}(__sanitizer_cov_trace_div8)=0xc3
set {unsigned char}(__sanitizer_cov_trace_gep)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_guard)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_guard_init)=0xc3
set {unsigned char}(__sanitizer_cov_trace_pc_indir)=0xc3
set {unsigned char}(__sanitizer_cov_trace_switch)=0xc3

# Insert (int3 ; vmcall) on the LLVMFuzzerTestOneInput 
set {unsigned char}(LLVMFuzzerTestOneInput+0x0)=0xcc
set {unsigned char}(LLVMFuzzerTestOneInput+0x1)=0x0f
set {unsigned char}(LLVMFuzzerTestOneInput+0x2)=0x01
set {unsigned char}(LLVMFuzzerTestOneInput+0x3)=0xc1
set {unsigned char}(LLVMFuzzerTestOneInput+0x4)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x5)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x6)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x7)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x8)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0x9)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xa)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xb)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xc)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xd)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xe)=0xcd
set {unsigned char}(LLVMFuzzerTestOneInput+0xf)=0xcd

# Continue execution until the LLVMFuzzerTestOneInput and take the snapshot as normal
continue
source $GDBPY
ni
ni
quit

EOF
else
    cat > "$DIR/$GDBCMDS" <<EOF
$(printf "$LOAD_SYMBOL_FILE")
set pagination off
run
source $GDBPY
ni
ni
quit

EOF
fi
chmod a+r "$DIR/$GDBCMDS"


# e.g., if we are in initramfs we need a script to run `/etc/rc.local`
if [[ ! -e "$DIR/init" ]]; then
  cat > "$DIR/init" <<EOF
#!/bin/sh

export PATH=\$PATH:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

echo "[+] Mounting /dev /proc /sys"
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp

echo "[+] bringing up loopback netdevice"

if command -v ip >/dev/null 2>&1; then
  ip link set up dev lo
else
  ifconfig lo: 127.0.0.1 netmask 255.0.0.0 up
fi

# for interactive use - enable shell prompt
# /sbin/getty -n -l /bin/sh 115200 /dev/console

echo "[+] Starting rc.local commands"
/etc/rc.local
echo "[+] rc.local finished with \$?"
if [ \$? -ne 0 ]; then
    echo "[ERROR] rc.local error"
fi


echo "[+] poweroff"
# try several poweroff/shutdown options... otherwise. kernel panic.
poweroff -f || shutdown -P now || busybox poweroff -f || /busybox poweroff -f || $BUSYBOX_STATIC poweroff -f

EOF
    chmod +x "$DIR/init"
fi

# copy some required utils
# statically built busybox installed from system package
cp "$(which busybox)" "$DIR/$BUSYBOX_STATIC"


log_success "done preparing root filesystem"

if [[ "$SNAPCHANGE_DEV" -eq 1 ]]; then
    echo "----------------------------------------"
    echo "!!! Sanity check the startup script !!!"
    cat "$RC_LOCAL"
fi
echo "----------------------------------------"
echo "!!! Sanity check the harness root '/' directory !!!"
ls -la "$DIR"
echo "----------------------------------------"
if [[ -n "$SNAPSHOT_ENTRYPOINT_CWD" ]]; then
  echo "!!! Sanity check the harness working directory !!!"
  ls -la "$DIR/$SNAPSHOT_ENTRYPOINT_CWD"
  echo "----------------------------------------"
fi

log_msg "converting root fs to bootable $IMGTYPE"

if [[ "$IMGTYPE" = "initramfs" ]]; then
    pushd "$DIR"
    find . -print0 \
        | cpio --null --create --owner root:root --format=newc \
        | lz4c -l \
        > "/snapchange/$RELEASE.initramfs.lz4"
    popd
elif [[ "$IMGTYPE" = "disk" ]]; then
    # Build a disk image
    virt-make-fs "$DIR" "/snapchange/$RELEASE.img"
else
    echo "[ERROR] invalid IMGTYPE=$IMGTYPE"
    exit 1
fi

log_success "done"
