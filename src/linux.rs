//! Linux specific structs

use anyhow::{anyhow, ensure, Result};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::fuzzer::Fuzzer;
use crate::fuzzvm::FuzzVm;
use crate::VirtAddr;

/// Signal with signal code and field
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum Signal {
    /// Illegal instruction signal
    IllegalInstruction {
        /// SIGILL code
        code: SigIllCode,

        /// Faulting address
        address: u64,
    },

    /// Segmentation fault signal
    SegmentationFault {
        /// SIGSEGV code
        code: SigSegvCode,

        /// Faulting address
        address: u64,
    },

    /// SIGTRAP signal
    Trap,

    /// Unimplemented signal
    Unknown {
        /// Unknown hit signal
        signal: i32,

        /// Code for the unknown signal
        code: u32,

        /// Argument for the unknown signal
        arg: u64,
    },
}

/// Code specific for SIGSEGV
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SigSegvCode {
    /// Address not mapped to object
    AddressNotMappedToObject,

    /// Invalid permissions for mapped object
    InvalidPermissionsForMappedObject,

    /// Failed address bound checks
    FailedAddressBoundChecks,

    /// Failed protection key checks
    FailedProtectionKeyChecks,

    /// ADI not enabled for mapped object
    AdiNotEnabledForMappedObject,

    /// Disrupting MCD error
    DisruptingMcdError,

    /// Precise MCD exception
    PreciseMcdException,

    /// Asynchronous ARM MTE error
    AsyncArmMteError,

    /// Synchronous ARM MTE error
    SyncArmMteError,

    /// Unknown code
    Unknown(u32),
}

/// Code specific for SIGILL
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum SigIllCode {
    /// Illegal opcode
    IllegalOpcode,

    /// Illegal operand
    IllegalOperand,

    /// Illegal addressing mode
    IllegalAddressingMode,

    /// Illegal trap
    IllegalTrap,

    /// Privileged opcode
    PrivilegedOpcode,

    /// Privileged register
    PrivilegedRegister,

    /// Coprocessor error
    CoprocessorError,

    /// Internal stack error
    InternalStackError,

    /// Unimplemented instruction address
    UnimplementedInstructionAddress,

    /// Illegal break
    IllegalBreak,

    /// Bundle update (modification) in process
    BundleUpdateInProcess,

    /// Unknown code
    Unknown(u32),
}

/// Fault caused by an out of bounds read or write in the kernel
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum KasanFault {
    /// Fault caused by read
    Read,

    /// Fault caused by write
    Write,
}

/// Parsed report data from the KASAN report
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub struct KasanReport {
    /// Out of bounds address causing the crash
    addr: u64,

    /// Size of the read/write causing the crash
    size: u64,

    /// Type of out of bounds access
    type_: KasanFault,

    /// Instruction address causing the crash
    ip: u64,
}

#[allow(dead_code)]
impl<'a, FUZZER: Fuzzer> FuzzVm<'a, FUZZER> {
    /// Get the signal during the `.force_sig_fault` call
    ///  
    /// # Errors
    ///
    /// * Failed to get a symbol at the current RIP. We should only attempt to parse the
    ///   signal during a known call to `force_sig_fault`
    pub fn forced_signal(&mut self) -> Result<Signal> {
        let curr_symbol: String = self
            .get_symbol(self.rip())
            .ok_or_else(|| anyhow!("Unknown symbol at {:#x}", self.rip()))?;

        ensure!(
            curr_symbol.contains("force_sig_fault"),
            "Attempted to get forced signal not at the force_sig_fault symbol"
        );

        // Get the signal parameters from the guest state
        let signal = i32::try_from(self.edi())?;
        let code = self.esi();
        let address = self.rdx();

        // Parse the signal parameters
        let signal = match signal {
            libc::SIGSEGV => {
                let code = match code {
                    1 => SigSegvCode::AddressNotMappedToObject,
                    2 => SigSegvCode::InvalidPermissionsForMappedObject,
                    3 => SigSegvCode::FailedAddressBoundChecks,
                    4 => SigSegvCode::FailedProtectionKeyChecks,
                    5 => SigSegvCode::AdiNotEnabledForMappedObject,
                    6 => SigSegvCode::DisruptingMcdError,
                    7 => SigSegvCode::PreciseMcdException,
                    8 => SigSegvCode::AsyncArmMteError,
                    9 => SigSegvCode::SyncArmMteError,
                    _ => SigSegvCode::Unknown(code),
                };

                Signal::SegmentationFault { code, address }
            }
            libc::SIGILL => {
                let code = match code {
                    1 => SigIllCode::IllegalOpcode,
                    2 => SigIllCode::IllegalOperand,
                    3 => SigIllCode::IllegalAddressingMode,
                    4 => SigIllCode::IllegalTrap,
                    5 => SigIllCode::PrivilegedOpcode,
                    6 => SigIllCode::PrivilegedRegister,
                    7 => SigIllCode::CoprocessorError,
                    8 => SigIllCode::InternalStackError,
                    9 => SigIllCode::UnimplementedInstructionAddress,
                    10 => SigIllCode::IllegalBreak,
                    11 => SigIllCode::BundleUpdateInProcess,
                    _ => SigIllCode::Unknown(code),
                };

                Signal::IllegalInstruction { code, address }
            }
            libc::SIGTRAP => Signal::Trap,
            _ => Signal::Unknown {
                signal,
                code,
                arg: address,
            },
        };

        // Return parsed signal
        Ok(signal)
    }
}

/// `PtRegs` structure passed to `__die`
#[derive(Debug, Copy, Clone)]
#[allow(dead_code, missing_docs, clippy::missing_docs_in_private_items)]
pub struct PtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
}

/// Linux syscalls
///
/// <https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/>
#[repr(u64)]
#[allow(non_camel_case_types, missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, TryFromPrimitive, IntoPrimitive)]
pub enum Syscall {
    sys_read = 0,
    sys_write = 1,
    sys_open = 2,
    sys_close = 3,
    sys_stat = 4,
    sys_fstat = 5,
    sys_lstat = 6,
    sys_poll = 7,
    sys_lseek = 8,
    sys_mmap = 9,
    sys_mprotect = 10,
    sys_munmap = 11,
    sys_brk = 12,
    sys_rt_sigaction = 13,
    sys_rt_sigprocmask = 14,
    sys_rt_sigreturn = 15,
    sys_ioctl = 16,
    sys_pread64 = 17,
    sys_pwrite64 = 18,
    sys_readv = 19,
    sys_writev = 20,
    sys_access = 21,
    sys_pipe = 22,
    sys_select = 23,
    sys_sched_yield = 24,
    sys_mremap = 25,
    sys_msync = 26,
    sys_mincore = 27,
    sys_madvise = 28,
    sys_shmget = 29,
    sys_shmat = 30,
    sys_shmctl = 31,
    sys_dup = 32,
    sys_dup2 = 33,
    sys_pause = 34,
    sys_nanosleep = 35,
    sys_getitimer = 36,
    sys_alarm = 37,
    sys_setitimer = 38,
    sys_getpid = 39,
    sys_sendfile = 40,
    sys_socket = 41,
    sys_connect = 42,
    sys_accept = 43,
    sys_sendto = 44,
    sys_recvfrom = 45,
    sys_sendmsg = 46,
    sys_recvmsg = 47,
    sys_shutdown = 48,
    sys_bind = 49,
    sys_listen = 50,
    sys_getsockname = 51,
    sys_getpeername = 52,
    sys_socketpair = 53,
    sys_setsockopt = 54,
    sys_getsockopt = 55,
    sys_clone = 56,
    sys_fork = 57,
    sys_vfork = 58,
    sys_execve = 59,
    sys_exit = 60,
    sys_wait4 = 61,
    sys_kill = 62,
    sys_uname = 63,
    sys_semget = 64,
    sys_semop = 65,
    sys_semctl = 66,
    sys_shmdt = 67,
    sys_msgget = 68,
    sys_msgsnd = 69,
    sys_msgrcv = 70,
    sys_msgctl = 71,
    sys_fcntl = 72,
    sys_flock = 73,
    sys_fsync = 74,
    sys_fdatasync = 75,
    sys_truncate = 76,
    sys_ftruncate = 77,
    sys_getdents = 78,
    sys_getcwd = 79,
    sys_chdir = 80,
    sys_fchdir = 81,
    sys_rename = 82,
    sys_mkdir = 83,
    sys_rmdir = 84,
    sys_creat = 85,
    sys_link = 86,
    sys_unlink = 87,
    sys_symlink = 88,
    sys_readlink = 89,
    sys_chmod = 90,
    sys_fchmod = 91,
    sys_chown = 92,
    sys_fchown = 93,
    sys_lchown = 94,
    sys_umask = 95,
    sys_gettimeofday = 96,
    sys_getrlimit = 97,
    sys_getrusage = 98,
    sys_sysinfo = 99,
    sys_times = 100,
    sys_ptrace = 101,
    sys_getuid = 102,
    sys_syslog = 103,
    sys_getgid = 104,
    sys_setuid = 105,
    sys_setgid = 106,
    sys_geteuid = 107,
    sys_getegid = 108,
    sys_setpgid = 109,
    sys_getppid = 110,
    sys_getpgrp = 111,
    sys_setsid = 112,
    sys_setreuid = 113,
    sys_setregid = 114,
    sys_getgroups = 115,
    sys_setgroups = 116,
    sys_setresuid = 117,
    sys_getresuid = 118,
    sys_setresgid = 119,
    sys_getresgid = 120,
    sys_getpgid = 121,
    sys_setfsuid = 122,
    sys_setfsgid = 123,
    sys_getsid = 124,
    sys_capget = 125,
    sys_capset = 126,
    sys_rt_sigpending = 127,
    sys_rt_sigtimedwait = 128,
    sys_rt_sigqueueinfo = 129,
    sys_rt_sigsuspend = 130,
    sys_sigaltstack = 131,
    sys_utime = 132,
    sys_mknod = 133,
    sys_uselib = 134,
    sys_personality = 135,
    sys_ustat = 136,
    sys_statfs = 137,
    sys_fstatfs = 138,
    sys_sysfs = 139,
    sys_getpriority = 140,
    sys_setpriority = 141,
    sys_sched_setparam = 142,
    sys_sched_getparam = 143,
    sys_sched_setscheduler = 144,
    sys_sched_getscheduler = 145,
    sys_sched_get_priority_max = 146,
    sys_sched_get_priority_min = 147,
    sys_sched_rr_get_interval = 148,
    sys_mlock = 149,
    sys_munlock = 150,
    sys_mlockall = 151,
    sys_munlockall = 152,
    sys_vhangup = 153,
    sys_modify_ldt = 154,
    sys_pivot_root = 155,
    sys__sysctl = 156,
    sys_prctl = 157,
    sys_arch_prctl = 158,
    sys_adjtimex = 159,
    sys_setrlimit = 160,
    sys_chroot = 161,
    sys_sync = 162,
    sys_acct = 163,
    sys_settimeofday = 164,
    sys_mount = 165,
    sys_umount2 = 166,
    sys_swapon = 167,
    sys_swapoff = 168,
    sys_reboot = 169,
    sys_sethostname = 170,
    sys_setdomainname = 171,
    sys_iopl = 172,
    sys_ioperm = 173,
    sys_create_module = 174,
    sys_init_module = 175,
    sys_delete_module = 176,
    sys_get_kernel_syms = 177,
    sys_query_module = 178,
    sys_quotactl = 179,
    sys_nfsservctl = 180,
    sys_getpmsg = 181,
    sys_putpmsg = 182,
    sys_afs_syscall = 183,
    sys_tuxcall = 184,
    sys_security = 185,
    sys_gettid = 186,
    sys_readahead = 187,
    sys_setxattr = 188,
    sys_lsetxattr = 189,
    sys_fsetxattr = 190,
    sys_getxattr = 191,
    sys_lgetxattr = 192,
    sys_fgetxattr = 193,
    sys_listxattr = 194,
    sys_llistxattr = 195,
    sys_flistxattr = 196,
    sys_removexattr = 197,
    sys_lremovexattr = 198,
    sys_fremovexattr = 199,
    sys_tkill = 200,
    sys_time = 201,
    sys_futex = 202,
    sys_sched_setaffinity = 203,
    sys_sched_getaffinity = 204,
    sys_set_thread_area = 205,
    sys_io_setup = 206,
    sys_io_destroy = 207,
    sys_io_getevents = 208,
    sys_io_submit = 209,
    sys_io_cancel = 210,
    sys_get_thread_area = 211,
    sys_lookup_dcookie = 212,
    sys_epoll_create = 213,
    sys_epoll_ctl_old = 214,
    sys_epoll_wait_old = 215,
    sys_remap_file_pages = 216,
    sys_getdents64 = 217,
    sys_set_tid_address = 218,
    sys_restart_syscall = 219,
    sys_semtimedop = 220,
    sys_fadvise64 = 221,
    sys_timer_create = 222,
    sys_timer_settime = 223,
    sys_timer_gettime = 224,
    sys_timer_getoverrun = 225,
    sys_timer_delete = 226,
    sys_clock_settime = 227,
    sys_clock_gettime = 228,
    sys_clock_getres = 229,
    sys_clock_nanosleep = 230,
    sys_exit_group = 231,
    sys_epoll_wait = 232,
    sys_epoll_ctl = 233,
    sys_tgkill = 234,
    sys_utimes = 235,
    sys_vserver = 236,
    sys_mbind = 237,
    sys_set_mempolicy = 238,
    sys_get_mempolicy = 239,
    sys_mq_open = 240,
    sys_mq_unlink = 241,
    sys_mq_timedsend = 242,
    sys_mq_timedreceive = 243,
    sys_mq_notify = 244,
    sys_mq_getsetattr = 245,
    sys_kexec_load = 246,
    sys_waitid = 247,
    sys_add_key = 248,
    sys_request_key = 249,
    sys_keyctl = 250,
    sys_ioprio_set = 251,
    sys_ioprio_get = 252,
    sys_inotify_init = 253,
    sys_inotify_add_watch = 254,
    sys_inotify_rm_watch = 255,
    sys_migrate_pages = 256,
    sys_openat = 257,
    sys_mkdirat = 258,
    sys_mknodat = 259,
    sys_fchownat = 260,
    sys_futimesat = 261,
    sys_newfstatat = 262,
    sys_unlinkat = 263,
    sys_renameat = 264,
    sys_linkat = 265,
    sys_symlinkat = 266,
    sys_readlinkat = 267,
    sys_fchmodat = 268,
    sys_faccessat = 269,
    sys_pselect6 = 270,
    sys_ppoll = 271,
    sys_unshare = 272,
    sys_set_robust_list = 273,
    sys_get_robust_list = 274,
    sys_splice = 275,
    sys_tee = 276,
    sys_sync_file_range = 277,
    sys_vmsplice = 278,
    sys_move_pages = 279,
    sys_utimensat = 280,
    sys_epoll_pwait = 281,
    sys_signalfd = 282,
    sys_timerfd_create = 283,
    sys_eventfd = 284,
    sys_fallocate = 285,
    sys_timerfd_settime = 286,
    sys_timerfd_gettime = 287,
    sys_accept4 = 288,
    sys_signalfd4 = 289,
    sys_eventfd2 = 290,
    sys_epoll_create1 = 291,
    sys_dup3 = 292,
    sys_pipe2 = 293,
    sys_inotify_init1 = 294,
    sys_preadv = 295,
    sys_pwritev = 296,
    sys_rt_tgsigqueueinfo = 297,
    sys_perf_event_open = 298,
    sys_recvmmsg = 299,
    sys_fanotify_init = 300,
    sys_fanotify_mark = 301,
    sys_prlimit64 = 302,
    sys_name_to_handle_at = 303,
    sys_open_by_handle_at = 304,
    sys_clock_adjtime = 305,
    sys_syncfs = 306,
    sys_sendmmsg = 307,
    sys_setns = 308,
    sys_getcpu = 309,
    sys_process_vm_readv = 310,
    sys_process_vm_writev = 311,
    sys_kcmp = 312,
    sys_finit_module = 313,
    sys_sched_setattr = 314,
    sys_sched_getattr = 315,
    sys_renameat2 = 316,
    sys_seccomp = 317,
    sys_getrandom = 318,
    sys_memfd_create = 319,
    sys_kexec_file_load = 320,
    sys_bpf = 321,
    stub_execveat = 322,
    userfaultfd = 323,
    membarrier = 324,
    mlock2 = 325,
    copy_file_range = 326,
    preadv2 = 327,
    pwritev2 = 328,
    pkey_mprotect = 329,
    pkey_alloc = 330,
    pkey_free = 331,
    statx = 332,
    io_pgetevents = 333,
    rseq = 334,
    Unknown = 0xdead,
}

/// The offset relative to the start of the file to begin a file seek
#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum Whence {
    /// The file offset is set to `offset` bytes
    Set = 0,

    /// The file offset is set to its current location plus `offset` bytes
    Current = 1,

    /// The file offset is set to the size of the file plus `offset` bytes
    End = 2,

    /// Unknown value parsed
    Unknown(u8),
}

impl From<u64> for Whence {
    fn from(val: u64) -> Whence {
        #[allow(clippy::cast_possible_truncation)]
        let val = val as u8;
        match val {
            0 => Whence::Set,
            1 => Whence::Current,
            2 => Whence::End,
            x => Whence::Unknown(x),
        }
    }
}

/// Create a function to parse the arguments for a linux function from the current
/// [`Fuzzvm`](crate::fuzzvm::FuzzVm) state
macro_rules! linux_args {
    ($func:ident, $ret:ident, $arg1:ident $arg1_ty:ty) => {
        #[allow(dead_code)]
        #[derive(Copy, Clone, Debug)]
        #[allow(missing_docs)]
        pub struct $ret {
            pub $arg1: $arg1_ty,
        }

        /// Get the arguments for an `lseek` system call
        #[allow(dead_code)]
        #[must_use]
        pub fn $func<FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> $ret {
            let $arg1 = fuzzvm.rdi().into();

            $ret { $arg1 }
        }
    };
    ($func:ident, $ret:ident, $arg1:ident $arg1_ty:ty, $arg2:ident $arg2_ty:ty) => {
        #[allow(dead_code)]
        #[derive(Copy, Clone, Debug)]
        #[allow(missing_docs)]
        pub struct $ret {
            pub $arg1: $arg1_ty,
            pub $arg2: $arg2_ty,
        }

        /// Get the arguments for an `lseek` system call
        #[allow(dead_code)]
        #[must_use]
        pub fn $func<FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> $ret {
            let $arg1: $arg1_ty = match core::mem::size_of::<$arg1_ty>() {
                2 => fuzzvm.rdi() & 0xffff,
                4 => fuzzvm.rdi() & 0xffff_ffff,
                8 => fuzzvm.rdi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg2: $arg2_ty = match core::mem::size_of::<$arg2_ty>() {
                2 => fuzzvm.rsi() & 0xffff,
                4 => fuzzvm.rsi() & 0xffff_ffff,
                8 => fuzzvm.rsi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            $ret { $arg1, $arg2 }
        }
    };
    ($func:ident, $ret:ident, $arg1:ident $arg1_ty:ty, $arg2:ident $arg2_ty:ty, $arg3:ident $arg3_ty:ty) => {
        #[allow(dead_code)]
        #[derive(Copy, Clone, Debug)]
        #[allow(missing_docs)]
        pub struct $ret {
            pub $arg1: $arg1_ty,
            pub $arg2: $arg2_ty,
            pub $arg3: $arg3_ty,
        }

        /// Get the arguments for an `lseek` system call
        #[allow(dead_code)]
        #[must_use]
        pub fn $func<FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> $ret {
            let $arg1: $arg1_ty = match core::mem::size_of::<$arg1_ty>() {
                2 => fuzzvm.rdi() & 0xffff,
                4 => fuzzvm.rdi() & 0xffff_ffff,
                8 => fuzzvm.rdi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg2: $arg2_ty = match core::mem::size_of::<$arg2_ty>() {
                2 => fuzzvm.rsi() & 0xffff,
                4 => fuzzvm.rsi() & 0xffff_ffff,
                8 => fuzzvm.rsi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg3: $arg3_ty = match core::mem::size_of::<$arg3_ty>() {
                2 => fuzzvm.rdx() & 0xffff,
                4 => fuzzvm.rdx() & 0xffff_ffff,
                8 => fuzzvm.rdx(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            $ret {
                $arg1,
                $arg2,
                $arg3,
            }
        }
    };
    ($func:ident,
            $ret:ident,
            $arg1:ident $arg1_ty:ty,
            $arg2:ident $arg2_ty:ty,
            $arg3:ident $arg3_ty:ty,
            $arg4:ident $arg4_ty:ty) => {
        #[derive(Copy, Clone, Debug)]
        #[allow(dead_code)]
        #[allow(missing_docs)]
        pub struct $ret {
            pub $arg1: $arg1_ty,
            pub $arg2: $arg2_ty,
            pub $arg3: $arg3_ty,
            pub $arg4: $arg4_ty,
        }

        /// Get the arguments for an `lseek` system call
        #[allow(dead_code)]
        #[must_use]
        pub fn $func<FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> $ret {
            let $arg1: $arg1_ty = match core::mem::size_of::<$arg1_ty>() {
                2 => fuzzvm.rdi() & 0xffff,
                4 => fuzzvm.rdi() & 0xffff_ffff,
                8 => fuzzvm.rdi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg2: $arg2_ty = match core::mem::size_of::<$arg2_ty>() {
                2 => fuzzvm.rsi() & 0xffff,
                4 => fuzzvm.rsi() & 0xffff_ffff,
                8 => fuzzvm.rsi(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg3: $arg3_ty = match core::mem::size_of::<$arg3_ty>() {
                2 => fuzzvm.rdx() & 0xffff,
                4 => fuzzvm.rdx() & 0xffff_ffff,
                8 => fuzzvm.rdx(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            let $arg4: $arg4_ty = match core::mem::size_of::<$arg4_ty>() {
                2 => fuzzvm.rcx() & 0xffff,
                4 => fuzzvm.rcx() & 0xffff_ffff,
                8 => fuzzvm.rcx(),
                _ => unimplemented!(),
            }
            .try_into()
            .unwrap();

            $ret {
                $arg1,
                $arg2,
                $arg3,
                $arg4,
            }
        }
    };
}

// Syscall implementations
linux_args!(lseek_args, LseekArgs, fd u64, offset u32, whence Whence);
linux_args!(read_args, ReadArgs, fd u64, buf VirtAddr, count u64);

// Libc implementations
linux_args!(fseek_args, FseekArgs, stream u64, offset u64, whence Whence);
linux_args!(fread_args, FreadArgs, ptr VirtAddr, size u64, nmemb u64, stream u64);
linux_args!(pread_args, PreadArgs, fd u64, buf VirtAddr, count usize, offset usize);
linux_args!(fopen_args, FopenArgs, path VirtAddr, mode VirtAddr);
linux_args!(fopen64_args, Fopen64Args, path VirtAddr, mode VirtAddr);
linux_args!(fclose_args, FcloseArgs, stream u64);
linux_args!(io_getc_args, IoGetcArgs, stream VirtAddr);
linux_args!(io_ungetc_args, IoUnGetcArgs, byte u64, stream VirtAddr);
linux_args!(io_file_read_args, IoFileReadArgs, stream VirtAddr, buf VirtAddr, count u64);
linux_args!(io_file_open_args, IoFileOpenArgs, stream VirtAddr, filename VirtAddr, posix_mode u32, prot u32);
linux_args!(io_getdelim, IoGetDelimArgs, lineptr_addr VirtAddr, size_addr VirtAddr, delimiter u32, stream u64);
linux_args!(free_args, FreeArgs, ptr VirtAddr);

/// get the first N args according to system v abi calling convetions: `rdi, rsi, rdx, rcx, r8, r9`
///
/// ```rust,ignore
/// let [_, arg2, _, arg4] = snapchange::linux::sysv_args(fuzzvm);
/// ```
pub fn sysv_args<const N: usize, FUZZER: Fuzzer>(fuzzvm: &FuzzVm<FUZZER>) -> [u64; N] {
    let regs = fuzzvm.regs();
    let mut args = [0u64; N];
    if N >= 1 {
        args[0] = regs.rdi;
    }
    if N >= 2 {
        args[1] = regs.rsi;
    }
    if N >= 3 {
        args[2] = regs.rdx;
    }
    if N >= 4 {
        args[3] = regs.rcx;
    }
    if N >= 5 {
        args[4] = regs.r8;
    }
    if N >= 6 {
        args[5] = regs.r9;
    }
    args
}
