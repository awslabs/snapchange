//! Initializers for timers used to kick the guest `vCPU` out of execution

use anyhow::{anyhow, Result};
use libc::c_int;

use nix::errno::Errno;
use nix::sys::signal::{
    pthread_sigmask, sigaction, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal,
};

use std::sync::atomic::Ordering;
use std::time::Duration;

/// Defines the timer value used by `setitimer`
#[repr(C)]
#[derive(Debug, Clone)]
struct Itimerval {
    /// Interval for periodic timer
    pub it_interval: Timeval,

    /// Time until next expiration
    pub it_value: Timeval,
}

/// Defines the interval for the timer
#[repr(C)]
#[derive(Debug, Clone, Default)]
struct Timeval {
    /// Seconds
    pub tv_sec: i64,

    /// Microseconds
    pub tv_usec: i64,
}

/// Defines which type of timer is enabled and which signal is generated which the timer
/// expires
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum WhichTimer {
    /// This timer counts down in real (i.e., wall clock) time.  At each expiration, a
    /// SIGALRM signal is generated.
    Real = 0,

    /// This timer counts down against the user-mode CPU time consumed by the process.
    /// (The measurement  includes  CPU time consumed by all threads in the process.)  At
    /// each expiration, a SIGVTALRM signal is generated.
    Virtual = 1,

    /// This timer counts down against the total (i.e., both user and system) CPU time
    /// consumed by the process.  (The measurement includes CPU time consumed by all
    /// threads in the process.)  At each expiration, a SIGPROF signal is generated.  
    ///
    /// In conjunction with ITIMER_VIRTUAL, this timer can be used to profile user and
    /// system CPU time consumed by the process.
    Profile = 2,
}

extern "C" {
    fn setitimer(which: WhichTimer, new_value: *mut Itimerval, old_value: *mut Itimerval) -> c_int;
}

/// A timer that, when expires, triggers a signal to be generated
pub(crate) struct Timer;

impl Timer {
    /// Create a new [`Timer`] that expires every `frequency` microseconds
    pub fn start(which: WhichTimer, frequency: Duration) -> Result<()> {
        /// Number of microseconds in a second
        const MICROSEC_IN_SECOND: u64 = 1_000_000;

        // Get the duration in microseconds
        #[allow(clippy::cast_possible_truncation)]
        let frequency = u64::try_from(frequency.as_micros())?;

        // Create the interval for the given microsecond frequency
        let interval = Timeval {
            tv_sec: i64::try_from(frequency / MICROSEC_IN_SECOND)?,
            tv_usec: i64::try_from(frequency % MICROSEC_IN_SECOND)?,
        };

        // Create the timer value for the given interval
        let mut timer_val = Itimerval {
            it_interval: interval.clone(),
            it_value: interval,
        };

        // Set the timer
        let ret = unsafe { setitimer(which, &mut timer_val, std::ptr::null_mut()) };

        if ret == 0 {
            Ok(())
        } else {
            Err(anyhow!(Errno::last()))
        }
    }
}

/// Handles the `SIGALRM` signal
extern "C" fn handler_alarm(_val: libc::c_int) {
    // Signal main thread to kick cores
    crate::KICK_CORES.store(true, Ordering::SeqCst);
}

/// Initialize the kick timer to periodically kick the `vCPU` out of the guest
pub(crate) fn init_kick_timer() -> Result<()> {
    // Set the SIGALRM signal handler
    unsafe {
        sigaction(
            Signal::SIGALRM,
            &SigAction::new(
                SigHandler::Handler(handler_alarm),
                SaFlags::empty(),
                SigSet::empty(),
            ),
        )?
    };

    let mut curr_sigset = SigSet::empty();

    // Get the current unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, None, Some(&mut curr_sigset))?;

    // Add SIGALRM to the unblocked signal set
    curr_sigset.add(Signal::SIGALRM);

    // Update the unblocked signal set
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&curr_sigset), None)?;

    // Start the timer
    Timer::start(WhichTimer::Real, Duration::from_millis(1000))?;

    Ok(())
}
