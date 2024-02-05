#!/usr/bin/env bash

# make sure env vars have sensible default if not set:

if [[ -z "$SNAPCHANGE_ROOT" ]]; then
  export SNAPCHANGE_ROOT="$(realpath "$(dirname "$0")../")"
fi
if [[ -z "$SNAPSHOT_INPUT" ]]; then
    DIR="$SNAPCHANGE_ROOT/image/"
else
  SNAPSHOT_INPUT="$(realpath "$SNAPSHOT_INPUT")"
  if [[ -d "$SNAPSHOT_INPUT" ]]; then
    DIR="$(realpath "$SNAPSHOT_INPUT")"
  else
    DIR="$(realpath -m ./image/)"
  fi
fi
if [[ -z "$SNAPSHOT_OUTPUT" ]]; then
  OUTPUT="$SNAPCHANGE_ROOT/snapshot/"
else
  OUTPUT="$(realpath -m "$SNAPSHOT_OUTPUT")"
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
else
    SNAPSHOT_FUNCTION="LLVMFuzzerTestOneInput"
fi
if [[ -z "$SNAPSHOT_FUNCTION" ]]; then
  SNAPSHOT_FUNCTION=""
fi
if [[ -z "$COVERAGE_BREAKPOINTS_EXTRA_BINS" ]]; then
    COVERAGE_BREAKPOINTS_EXTRA_BINS=""
fi
if [[ -z "$SNAPSHOT_EXTRACT" ]]; then
  SNAPSHOT_EXTRACT="$COVERAGE_BREAKPOINTS_EXTRA_BINS"
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
if [[ -z "$BUSYBOX_STATIC" ]]; then
    BUSYBOX_STATIC=/busybox.static
fi
if [[ -z "$SNAPSHOT_ENV" ]]; then
    SNAPSHOT_ENV=""
fi
if [[ -z "$SNAPSHOT_RUN_AFTER" ]]; then
    SNAPSHOT_RUN_AFTER=""
fi
if [[ -z "$SNAPSHOT_RUN_BEFORE" ]]; then
    SNAPSHOT_RUN_BEFORE=""
fi
if [[ -z "$SNAPSHOT_CUSTOM_LAUNCH_SCRIPT" ]]; then
    SNAPSHOT_CUSTOM_LAUNCH_SCRIPT=""
fi
if [[ -z "$SNAPSHOT_CUSTOM_GDBCMDS" ]]; then
    SNAPSHOT_CUSTOM_GDBCMDS=""
fi
if [[ -z "$SNAPSHOT_GDB_MODE" ]]; then
    SNAPSHOT_GDB_MODE="quit"
fi

source $SNAPCHANGE_ROOT/utils/log.sh || { echo "Failed to source $SNAPCHANGE_ROOT/utils/log.sh"; exit 1; }

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
  pushd "$DIR" >/dev/null
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

if [[ "$SNAPSHOT_FUNCTION" ]]; then 

    if ! nm "$BIN" | grep $SNAPSHOT_FUNCTION; then
        log_error "$SNAPSHOT_FUNCTION not found in $BIN."
        exit 1
    fi

    R2Z=""
    if command -v rizin >/dev/null 2>&1; then
        R2Z=rizin
    elif command -v r2 >/dev/null 2>&1; then
        R2Z=r2
    else
        log_error "please install radare2/rizin for patching"
        exit 1
    fi
    
    # If there is a snapshot function, dump the first 16 bytes of LLVMFuzzerTestOneInput to restore
    # after taking the snapshot. These bytes are corrupted 
    "$R2Z" -q -c "p8 16 @ sym.$SNAPSHOT_FUNCTION" $BIN > /tmp/libfuzzer.bytes.bak
    cat /tmp/libfuzzer.bytes.bak
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
#!/bin/sh

set -e

if test -e /etc/profile; then
    . /etc/profile
fi

export SNAPCHANGE=1

echo "[+] snapshotting program: $SNAPSHOT_ENTRYPOINT $SNAPSHOT_ENTRYPOINT_ARGUMENTS"

sysctl -w kernel.randomize_va_space=0 || true

EOF

if [[ "$SNAPCHANGE_DEV" -eq 1 ]]; then
    echo "set -x" >> "$RC_LOCAL"
fi

if test -n "$SNAPSHOT_ENV"; then
    for var in $SNAPSHOT_ENV; do
        echo "export $var" >> "$RC_LOCAL"
    done
fi

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
    pushd /tmp/
    # we build a small program that does nothing but trigger a pre-set
    # breakpoint. We can use this program to run gdb under root; wait till we
    # hit the breakpoint. dump all symbols (including kernel symbols) using the
    # normal gdb commands. Kernel symbols won't change across processes so this
    # is fine. However, we don't want symbols of the true.bp binary, so we
    # strip the binary.
    cat > true.bp.c <<EOF
int main(void) {
__asm("int3");
return 0;
}
EOF
    # we create the true.bp binary with CFLAGS to achieve minimal size
    make true.bp CFLAGS="-Os -static -s -ffunction-sections -fdata-sections -Wl,-gc-sections"
    strip true.bp
    du -H true.bp
    mv true.bp $DIR/
    rm true.bp.c
    popd

    cat >> "$RC_LOCAL" <<EOF
echo "[+] obtaining kernel symbols by running gdb as root"
\$GDB --batch --command=$GDBCMDS.basic --args /true.bp
mv /tmp/gdb.symbols /tmp/gdb.symbols.root
rm /tmp/gdb.modules
rm /tmp/gdb.vmmap
EOF
fi

if [[ -n "$SNAPSHOT_RUN_BEFORE" ]]; then
    echo "echo [+] executing run-before commands" >> $RC_LOCAL
    printf "$SNAPSHOT_RUN_BEFORE" >> $RC_LOCAL
    echo "" >> $RC_LOCAL
fi
echo "" >> $RC_LOCAL


if [[ -z "$SNAPSHOT_CUSTOM_LAUNCH_SCRIPT" ]] ; then
    echo "echo [+] launching target under gdb" >> $RC_LOCAL

    cat >> "$RC_LOCAL" <<EOF
# snapshot marker
export SNAPSHOT=1
export SNAPCHANGE_SNAPSHOT=1
touch /SNAPCHANGE_SNAPSHOT

EOF

    # If user is not root, run gdb under the given user
    if [ $USER != 'root' ]; then
        echo -n "su $USER -c \"" >> $RC_LOCAL
    fi

    if [[ "$SNAPCHANGE_DEV" -eq 1 ]]; then
        echo -n "echo '---- begin gdbcmds ----'" >> $RC_LOCAL
        echo -n "cat $GDBCMDS" >> $RC_LOCAL
        echo -n "echo '---- end gdbcmds ----'" >> $RC_LOCAL
    fi

    # Create the script to start on boot
    echo -n "\$GDB --batch --command=$GDBCMDS --args "$SNAPSHOT_ENTRYPOINT" $SNAPSHOT_ENTRYPOINT_ARGUMENTS" >> $RC_LOCAL

    # If user is not root, close the command executed
    if [ $USER != 'root' ]; then
        echo -n "\"" >> $RC_LOCAL
    fi

    # run in background
    echo " &" >> $RC_LOCAL
else
    echo "echo [+] launching target with $SNAPSHOT_CUSTOM_LAUNCH_SCRIPT" >> "$RC_LOCAL"
    ls -al "$SNAPSHOT_CUSTOM_LAUNCH_SCRIPT" || true
    echo "$SNAPSHOT_CUSTOM_LAUNCH_SCRIPT &" >> "$RC_LOCAL"
fi

echo "" >> $RC_LOCAL

if [[ -n "$SNAPSHOT_RUN_AFTER" ]]; then
    echo "echo [+] executing run-after commands" >> $RC_LOCAL
    printf "$SNAPSHOT_RUN_AFTER" >> $RC_LOCAL
    echo "" >> $RC_LOCAL
fi
echo "" >> $RC_LOCAL

echo "echo [+] waiting for processes to finish" >> $RC_LOCAL
echo "wait" >> $RC_LOCAL

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
cp $SNAPCHANGE_ROOT/utils/gdbsnapshot.py $DIR/$GDBPY
chmod a+r "$DIR/$GDBPY"

# Try to remove the old gdbcmds since we are writing a new one below
rm $DIR/$GDBCMDS || true

LOAD_SYMBOL_FILE=""
for try_load in $SYMBOL_FILE_PATHS; do
    if [[ -e "$DIR/$try_load" ]]; then
        LOAD_SYMBOL_FILE="add-symbol-file $try_load \n$LOAD_SYMBOL_FILE"
    fi
done


SANITIZER_FUNCTIONS=''
if nm "$BIN" | grep __sanitizer_cov_trace_; then
    SANITIZER_FUNCTIONS="
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
    "
fi


cat > "$DIR/$GDBCMDS.basic" <<EOF
$(printf "$LOAD_SYMBOL_FILE")
set pagination off
run
bt
x/2i \$rip
source $GDBPY
ni
ni
quit

EOF


cat > "$DIR/$GDBCMDS.detach" <<EOF
$(printf "$LOAD_SYMBOL_FILE")
set pagination off
run
bt
x/2i \$rip
source $GDBPY
detach

EOF

# Execute to the first int3, execute the gdbsnapshot, execute vmcall, then exit
if [[ -n "$SNAPSHOT_CUSTOM_GDBCMDS" ]]; then
    if [[ -e "$SNAPSHOT_CUSTOM_GDBCMDS" ]]; then
        cp "$SNAPSHOT_CUSTOM_GDBCMDS" "$DIR/$GDBCMDS"
    elif [[ -e "$DIR/$SNAPSHOT_CUSTOM_GDBCMDS" ]]; then
        cp "$DIR/$SNAPSHOT_CUSTOM_GDBCMDS" "$DIR/$GDBCMDS"
    else
        log_error "failed to locate custom gdb commands: $SNAPSHOT_CUSTOM_GDBCMDS"
        exit 1
    fi
elif [[ "$SNAPSHOT_FUNCTION" ]]; then
    echo "FUNCTION SNAPSHOT DETECTED (e.g., libfuzzer)"
    echo "Taking a snapshot at $SNAPSHOT_FUNCTION"
    cat > "$DIR/$GDBCMDS" <<EOF
$(printf "$LOAD_SYMBOL_FILE")
set pagination off
# Ignore leak detection. 
set environment ASAN_OPTIONS=detect_leaks=0

# Stop at the first chance in the target in order to enable the breakpoint on $SNAPSHOT_FUNCTION
start
del *

$SANITIZER_FUNCTIONS

# Insert (int3 ; vmcall) on the $SNAPSHOT_FUNCTION 
set {unsigned char}($SNAPSHOT_FUNCTION+0x0)=0xcc
set {unsigned char}($SNAPSHOT_FUNCTION+0x1)=0x0f
set {unsigned char}($SNAPSHOT_FUNCTION+0x2)=0x01
set {unsigned char}($SNAPSHOT_FUNCTION+0x3)=0xc1
set {unsigned char}($SNAPSHOT_FUNCTION+0x4)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0x5)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0x6)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0x7)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0x8)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0x9)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xa)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xb)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xc)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xd)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xe)=0xcd
set {unsigned char}($SNAPSHOT_FUNCTION+0xf)=0xcd

x/16xb \$rip
x/16xb $SNAPSHOT_FUNCTION

# Continue execution until the $SNAPSHOT_FUNCTION and take the snapshot as normal
continue
printf "Sourcing gdb script\n"
source $GDBPY
printf "Single step 1"
x/16xb \$rip
ni
printf "Single step 2"
x/16xb \$rip
ni
printf "Single step 3"
x/16xb \$rip
quit

EOF
else
    if [[ "$SNAPSHOT_GDB_MODE" == "detach" ]]; then
        cp "$DIR/$GDBCMDS.detach" "$DIR/$GDBCMDS"
    else 
        if [[ "$SNAPSHOT_GDB_MODE" != "quit" ]]; then
            echo "Invalid SNAPSHOT_GDB_MODE=$SNAPSHOT_GDB_MODE - using \"quit\""
        fi
        cp "$DIR/$GDBCMDS.basic" "$DIR/$GDBCMDS"
    fi
fi
chmod a+r "$DIR/$GDBCMDS"
cat "$DIR/$GDBCMDS"


# e.g., if we are in initramfs we need a script to run `/etc/rc.local`
if [[ ! -e "$DIR/init" ]]; then
  cat > "$DIR/init" <<EOF
#!/bin/sh

# basic PATH setup... should be almost universal
export PATH=\$PATH:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin:/usr/local/sbin

if test -e /etc/profile; then
    . /etc/profile
fi

echo "[+] Mounting /dev /proc /sys"
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mkdir -p /dev/shm
mount -t tmpfs tmpfs /dev/shm

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
        > "$SNAPCHANGE_ROOT/$RELEASE.initramfs.lz4"
    popd
elif [[ "$IMGTYPE" = "disk" ]]; then
    # Build a disk image
    virt-make-fs "$DIR" "$SNAPCHANGE_ROOT/$RELEASE.img"
else
    echo "[ERROR] invalid IMGTYPE=$IMGTYPE"
    exit 1
fi

log_success "done"
