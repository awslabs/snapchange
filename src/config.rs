//! Configuration settings for Snapchange

use serde::{Deserialize, Serialize};

use std::time::Duration;

/// Configuration settings for a Snapchange fuzzer
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// The stats configuration settings
    pub stats: Stats,

    /// The redqueen configuration settings
    #[cfg(feature = "redqueen")]
    pub redqueen: Redqueen,

    /// Memory allocated for each guest
    pub guest_memory_size: u64,
}

/// Configurations settings specific for statistics gathering
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Stats {
    /// Length of timer, in milliseconds, for the coverage to be collected from and
    /// redistributed to the worker cores
    pub merge_coverage_timer: Duration,

    /// Maximum size of the new corpus handed to each core while distributing
    /// the main corpus
    pub maximum_new_corpus_size: usize,

    /// The minimum percentage of the total corpus used to create a new corpus when
    /// distributing the main corpus amongst the fuzzing cores
    pub minimum_total_corpus_percentage_sync: u8,

    /// The minimum percentage of the total corpus used to create a new corpus when
    /// distributing the main corpus amongst the fuzzing cores
    pub maximum_total_corpus_percentage_sync: u8,
}

/// Configurations settings specific to the redqueen implementation
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg(feature = "redqueen")]
pub struct Redqueen {
    /// Redqueen max entropy occurs if the number of instances of a rule
    /// can be applied is more than this threshold
    pub entropy_threshold: usize,

    /// A core exits the redqueen implementation if it exceeds this timeout
    pub timeout: Duration,

    /// Number of cores that can trigger redqueen
    pub cores: u64,
}

impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            guest_memory_size: 5 * 1024 * 1024 * 1024,
            stats: Stats::default(),
            #[cfg(feature = "redqueen")]
            redqueen: Redqueen::default(),
        }
    }
}

impl std::default::Default for Stats {
    fn default() -> Self {
        Self {
            merge_coverage_timer: Duration::from_secs(60),
            maximum_new_corpus_size: 250,
            minimum_total_corpus_percentage_sync: 10,
            maximum_total_corpus_percentage_sync: 50,
        }
    }
}

#[cfg(feature = "redqueen")]
impl std::default::Default for Redqueen {
    fn default() -> Self {
        Self {
            entropy_threshold: 100,
            timeout: Duration::from_secs(2),
            cores: 8,
        }
    }
}
