//! Configuration settings for Snapchange

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration settings for a Snapchange fuzzer
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// The stats configuration settings
    #[serde(default)]
    pub stats: Stats,

    /// The redqueen configuration settings
    #[cfg(feature = "redqueen")]
    #[serde(default)]
    pub redqueen: Redqueen,

    /// Memory allocated for each guest
    #[serde(default = "default_guest_memory_size")]
    pub guest_memory_size: u64,
}

/// Configurations settings specific for statistics gathering
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Stats {
    /// Length of timer, in milliseconds, for the coverage to be collected from and
    /// redistributed to the worker cores
    #[serde(default = "default_merge_coverage_timer")]
    pub merge_coverage_timer: Duration,

    /// Maximum size of the new corpus handed to each core while distributing
    /// the main corpus
    #[serde(default = "default_maximum_new_corpus_size")]
    pub maximum_new_corpus_size: usize,

    /// The minimum percentage of the total corpus used to create a new corpus when
    /// distributing the main corpus amongst the fuzzing cores
    #[serde(default = "default_minimum_total_corpus_percentage_sync")]
    pub minimum_total_corpus_percentage_sync: u8,

    /// The minimum percentage of the total corpus used to create a new corpus when
    /// distributing the main corpus amongst the fuzzing cores
    #[serde(default = "default_maximum_total_corpus_percentage_sync")]
    pub maximum_total_corpus_percentage_sync: u8,

    /// How often, in milliseconds, each fuzz core syncs its basic statistics with
    /// the main core.
    #[serde(default = "default_stats_sync")]
    pub stats_sync_timer: Duration,

    /// How often, in milliseconds, each fuzz core syncs its coverage with the
    /// main core. The larger the coverage, the longer this sync could take.
    /// Increasing this number will help reduce the amount of time in the StatsSync
    /// performance metric
    #[serde(default = "default_coverage_sync")]
    pub coverage_sync_timer: Duration,
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

    /// Use redqueen rules during random mutations
    #[serde(default = "default_mutate_by_redqueen_rules")]
    pub mutate_by_redqueen_rules: bool,
}

const fn default_maximum_total_corpus_percentage_sync() -> u8 {
    50
}

const fn default_minimum_total_corpus_percentage_sync() -> u8 {
    10
}

const fn default_maximum_new_corpus_size() -> usize {
    250
}

const fn default_merge_coverage_timer() -> Duration {
    Duration::from_secs(60)
}

const fn default_stats_sync() -> Duration {
    Duration::from_millis(500)
}

const fn default_coverage_sync() -> Duration {
    Duration::from_millis(2000)
}

const fn default_guest_memory_size() -> u64 {
    5 * 1024 * 1024 * 1024
}

const fn default_mutate_by_redqueen_rules() -> bool {
    false
}

impl std::default::Default for Config {
    fn default() -> Self {
        Self {
            guest_memory_size: default_guest_memory_size(),
            stats: Stats::default(),
            #[cfg(feature = "redqueen")]
            redqueen: Redqueen::default(),
        }
    }
}

impl std::default::Default for Stats {
    fn default() -> Self {
        Self {
            merge_coverage_timer: default_merge_coverage_timer(),
            stats_sync_timer: default_stats_sync(),
            coverage_sync_timer: default_coverage_sync(),
            maximum_new_corpus_size: default_maximum_new_corpus_size(),
            minimum_total_corpus_percentage_sync: default_minimum_total_corpus_percentage_sync(),
            maximum_total_corpus_percentage_sync: default_maximum_total_corpus_percentage_sync(),
        }
    }
}

#[cfg(feature = "redqueen")]
impl std::default::Default for Redqueen {
    fn default() -> Self {
        Self {
            entropy_threshold: 10,
            timeout: Duration::from_secs(60),
            cores: 4,
            mutate_by_redqueen_rules: false,
        }
    }
}
