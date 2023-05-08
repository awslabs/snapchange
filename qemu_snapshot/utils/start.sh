$PWD/QEMU/build/qemu-system-x86_64 \
	-m 4G \
	-smp 1 \
	-kernel $PWD/linux/arch/x86_64/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial" \
	-drive file=$PWD/IMAGE/bookworm.img \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
