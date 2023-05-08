//! `RomuDuoJr` pseudo random number generator implementation seeded by Lehmer64 seeded
//! by `rdtsc`
//!
//!
//!
//! ```test
//! Reference: https://www.romu-random.org/code.c
//!
//! //===== RomuDuoJr ==================================================================
//! //
//! // The fastest generator using 64-bit arith., but not suited for huge jobs.
//! // Est. capacity = 2^51 bytes. Register pressure = 4. State size = 128 bits.
//!
//! uint64_t xState, yState;  // set to nonzero seed
//!
//! uint64_t romuDuoJr_random () {
//!    uint64_t xp = xState;
//!    xState = 15241094284759029579u * yState;
//!    yState = yState - xp;  yState = ROTL(yState,27);
//!    return xp;
//! }
//! ```

/// `RomuDuoJr` pseudo random number generator
pub struct Rng {
    /// Internal x state
    xstate: u64,

    /// Internal y state
    ystate: u64,
}

impl Default for Rng {
    fn default() -> Self {
        Rng::new()
    }
}

impl rand::RngCore for Rng {
    #[allow(clippy::cast_possible_truncation)]
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.next()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl Rng {
    /// Creates a new `RandRomu` rng initialized with values from Lehmer64 initialized
    /// with `rdtsc`
    #[must_use]
    pub fn new() -> Rng {
        // Generate the random state from Lehmer64
        let mut lehmer64 = Lehmer64::new();
        let mut res = Rng {
            xstate: lehmer64.rand_u64(),
            ystate: lehmer64.rand_u64(),
        };

        // Cycle through to create some chaos
        for _ in 0..92 {
            let _ = res.next();
        }

        res
    }

    /// Create an [`Rng`] seeded with the given seed value
    pub fn from_seed(seed: u64) -> Rng {
        // Generate the random state from Lehmer64
        let mut lehmer64 = Lehmer64::from_seed(u128::from(seed));
        let mut res = Rng {
            xstate: lehmer64.rand_u64(),
            ystate: lehmer64.rand_u64(),
        };

        // Cycle through to create some chaos
        for _ in 0..92 {
            let _ = res.next();
        }

        res
    }

    /// Get the next random number
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u64 {
        let xp = self.xstate;
        self.xstate = 15_241_094_284_759_029_579_u64.wrapping_mul(self.ystate);
        self.ystate = self.ystate.wrapping_sub(xp);
        self.ystate = self.ystate.rotate_left(27);
        xp
    }

    /// Provides a u64 useful for fuzzing
    #[allow(clippy::cast_possible_truncation, clippy::cast_lossless, dead_code)]
    pub fn fuzz_u64(&mut self) -> u64 {
        let val = self.next();
        match self.next() % 16 {
            0 => val as u8 as u64,
            1 => val as u16 as u64,
            2 => val as u32 as u64,
            3 => (u8::MAX - (val as u8 % 16)) as u64,
            4 => (u8::MIN + (val as u8 % 16)) as u64,
            5 => (u16::MAX - (val as u16 % 16)) as u64,
            6 => (u16::MIN + (val as u16 % 16)) as u64,
            7 => (u32::MAX - (val as u32 % 16)) as u64,
            8 => (u32::MIN + (val as u32 % 16)) as u64,
            9 => u64::MAX - (val % 16),
            10 => u64::MIN + (val % 16),
            _ => val,
        }
    }
}

/// Rng seeded with `rdtsc` that is generated using Lehmer64
pub struct Lehmer64 {
    /// Internal state
    value: u128,
}

impl Default for Lehmer64 {
    fn default() -> Self {
        let mut res = Lehmer64 {
            value: u128::from(unsafe { core::arch::x86_64::_rdtsc() }),
        };

        // Cycle through to create some chaos
        for _ in 0..123 {
            let _ = res.rand_u64();
        }

        res
    }
}

impl Lehmer64 {
    /// Create a new `Lehmer64` rng seeded by `rdtsc`
    #[must_use]
    pub fn new() -> Lehmer64 {
        Lehmer64::default()
    }

    /// Create an [`Lehmer64`] seeded with the given seed value
    #[must_use]
    pub fn from_seed(seed: u128) -> Lehmer64 {
        Lehmer64 { value: seed }
    }

    /// Get the next random number
    #[allow(clippy::cast_possible_truncation)]
    fn rand_u64(&mut self) -> u64 {
        self.value = self.value.wrapping_mul(0xda94_2042_e4dd_58b5);
        (self.value >> 64) as u64
    }
}
