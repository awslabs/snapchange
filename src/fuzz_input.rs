//! Provides an abstraction around various types of fuzz inputs

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_hex::{CompactPfx, SerHex};

#[cfg(feature = "redqueen")]
use rustc_hash::FxHashSet;

use std::fmt::Debug;
use std::hash::Hash;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::feedback::FeedbackLog;
use crate::rng::Rng;

#[cfg(feature = "redqueen")]
use crate::cmp_analysis::RedqueenRule;

/// Returned by the [`FuzzInput::minimize`] function to signal how to progress further.
#[derive(Debug, Clone, Copy, Default)]
pub enum MinimizeControlFlow {
    /// Continue with minimization
    #[default]
    Continue,
    /// Stop minimization after the current step
    Stop,
    /// Skip the current step, e.g., because the current minimization rule could not be applied.
    Skip,
    /// Continue minimization for at least that many steps.
    ContinueFor(u32),
}

impl MinimizeControlFlow {
    /// continue minimization for at least one more iteration
    pub fn one_more() -> Self {
        Self::ContinueFor(1)
    }

    /// continue minimization
    pub fn cont() -> Self {
        Self::Continue
    }

    /// stop minimization after current step
    pub fn stop() -> Self {
        Self::Stop
    }
}

/// An abstract input used in fuzzing. This trait provides methods for mutating, generating, and
/// minimizing an input. This trait also has required methods for enabling Redqueen analysis
/// for an input.
pub trait FuzzInput:
    Sized + Debug + Default + Clone + Send + Hash + Eq + std::panic::UnwindSafe
{
    /// Type that represents minimization state. Use [`NullMinimizerState`] if you do not have a
    /// useful state for your minimization algorithm. The state type must implement the
    /// [`MinimizerState`] trait.
    type MinState: MinimizerState + std::panic::RefUnwindSafe;

    /// Function signature for a mutator of this type
    #[allow(clippy::type_complexity)]
    type MutatorFunc = fn(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
    ) -> Option<String>;

    /// Read the input bytes as the implemented type
    ///
    /// # Errors
    ///
    /// * Failed to convert the given bytes to `Self`
    fn from_bytes(bytes: &[u8]) -> Result<Self>;

    /// Convert the implemented type as a `Vec<u8>`
    ///
    /// # Errors
    ///
    /// * Failed to serialize `Self` into the output bytes
    fn to_bytes(&self, output: &mut Vec<u8>) -> Result<()>;

    /// Mutate the current object using a `corpus`, `rng`, and `dictionary` that has a
    /// maximum length of `max_length`. Returns the list of mutations applied during this
    /// mutation
    fn mutate(
        input: &mut Self,
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
        max_mutations: u64,
        #[cfg(feature = "redqueen")] redqueen_rules: Option<&FxHashSet<RedqueenRule>>,
    ) -> Vec<String>;

    /// Basic mutators available to mutate this fuzzer's input
    #[must_use]
    fn mutators() -> &'static [Self::MutatorFunc] {
        &[]
    }

    /// Expensive mutators available to mutate this fuzzer's input. These mutators are called
    /// less often on this type since they are potentially more costly
    #[must_use]
    fn expensive_mutators() -> &'static [Self::MutatorFunc] {
        &[]
    }

    /// Generate a random version of this type
    fn generate(
        corpus: &[Arc<InputWithMetadata<Self>>],
        rng: &mut Rng,
        dictionary: &Option<Vec<Vec<u8>>>,
        min_length: usize,
        max_length: usize,
    ) -> InputWithMetadata<Self>;

    /// init stateful minimization
    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
        panic!(
            "Minimize not implemented for {:?}",
            std::any::type_name::<Self>()
        );
    }

    /// Minimize the given `input` based on a minimization strategy
    fn minimize(
        &mut self,
        _state: &mut Self::MinState,
        _current_iteration: u32,
        _last_successful_iteration: u32,
        _rng: &mut Rng,
    ) -> MinimizeControlFlow {
        panic!(
            "Minimize not implemented for {:?}",
            std::any::type_name::<Self>()
        );
    }

    /// Get the hash for this input
    fn fuzz_hash(&self) -> u64 {
        crate::utils::calculate_hash(&self)
    }

    /// Type used to describe the locations in the input to apply a given rule
    #[cfg(feature = "redqueen")]
    type RuleCandidate: Debug;

    /// Apply the given [`RedqueenRule`] to the current input using the given candidate
    /// returning the mutation done
    #[cfg(feature = "redqueen")]
    fn apply_redqueen_rule(
        &mut self,
        _rule: &RedqueenRule,
        _candidate: &Self::RuleCandidate,
    ) -> Option<String> {
        panic!("Redqueen not implemented for this type. Please impl `apply_redqueen_rule`");
    }

    /// Upper bound for the ranges produced during increasing entropy for redqueen
    fn entropy_limit(&self) -> usize {
        panic!("Redqueen not implemented for this type. Please impl `entropy_limit`");
    }

    /// Increase entropy of the input between the given start and end values
    #[cfg(feature = "redqueen")]
    fn increase_entropy(&mut self, _rng: &mut Rng, _start: usize, _end: usize) -> Result<()> {
        panic!("Redqueen not implemented for this type. Please impl `increase_entropy`");
    }

    /// Get a list of all of the `RuleCandidate`s that the given `rule` can be applied to. These
    /// candidates are then passed to `apply_redqueen_rule` to deterministically search the
    /// applicable redqueen search space for this input
    #[cfg(feature = "redqueen")]
    fn get_redqueen_rule_candidates(&self, _rule: &RedqueenRule) -> Vec<Self::RuleCandidate> {
        panic!(
            "Redqueen not implemented for this type. Please impl `get_redqueen_rule_candidates`"
        );
    }

    /// Returns true if the given rule can be applied to this input. Used as a fast path instead of
    /// using get_redqueen_rule_candidates.
    #[cfg(feature = "redqueen")]
    fn has_redqueen_rule_candidates(&self, _rule: &RedqueenRule) -> bool {
        panic!(
            "Redqueen not implemented for this type. Please impl `has_redqueen_rule_candidates`"
        );
    }

    /// return some kind of entropy metric (e.g., byte entropy), if applicable.
    fn entropy_metric(&self) -> Option<f64> {
        None
    }

    /// return length of the input, if applicable.
    fn len(&self) -> Option<usize> {
        None
    }
}

/// This is the trait to implement when you want to do provide a type for stateful minimization.
/// See [`BytesMinimizeState`] for an example.
pub trait MinimizerState:
    Sized + Debug + Default + Clone + Send + Hash + Eq + std::panic::UnwindSafe
{
    /// Return true if the state is a stop state, i.e., there is nothing else to try.
    fn is_stop_state(&self) -> bool;
}

/// In case there is no useful minimization state, use this type as your minimization state.
///
/// ```rust,ignore
///
/// impl FuzzInput for YourType {
///    type MinState = NullMinimizerState;
///
///    fn init_minimize(&mut self) -> (Self::MinState, MinimizeControlFlow) {
///        NullMinimizerState::init()
///    }
///
/// }
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct NullMinimizerState;

impl MinimizerState for NullMinimizerState {
    fn is_stop_state(&self) -> bool {
        false
    }
}

#[allow(dead_code)]
impl NullMinimizerState {
    /// to be used in [`FuzzInput::
    pub const fn init() -> (Self, MinimizeControlFlow) {
        (Self {}, MinimizeControlFlow::Continue)
    }
}

/// Metadata about a crashing input or a new input that found new coverage.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct InputMetadata {
    /// Fuzz hash of the original file used for mutation
    #[serde(with = "SerHex::<CompactPfx>")]
    pub original_file: u64,

    /// Mutatation strategies used on this file
    pub mutations: Vec<String>,

    /// New coverage blocks hit by this input
    pub new_coverage: Vec<FeedbackLog>,

    /// Is this input the result of increased entropy
    pub entropy: bool,
}

/// An input tied with metadata about that input
pub struct InputWithMetadata<T: FuzzInput> {
    /// The input in question
    pub input: T,

    /// Metadata about this input
    pub metadata: RwLock<InputMetadata>,
}
impl<T: FuzzInput> std::panic::UnwindSafe for InputWithMetadata<T> {}
impl<T: FuzzInput> std::panic::RefUnwindSafe for InputWithMetadata<T> {}
unsafe impl<T: FuzzInput> Send for InputWithMetadata<T> {}
unsafe impl<T: FuzzInput> Sync for InputWithMetadata<T> {}

impl<T: FuzzInput> std::cmp::PartialEq for InputWithMetadata<T> {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input
    }
}
impl<T: FuzzInput> std::cmp::Eq for InputWithMetadata<T> {}

impl<T: FuzzInput> std::hash::Hash for InputWithMetadata<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.input.hash(state);
        self.metadata.read().unwrap().hash(state);
    }
}
impl<T: FuzzInput> std::default::Default for InputWithMetadata<T> {
    fn default() -> Self {
        Self {
            input: T::default(),
            metadata: RwLock::new(InputMetadata::default()),
        }
    }
}
impl<T: FuzzInput> std::ops::Deref for InputWithMetadata<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.input
    }
}
impl<T: FuzzInput> std::ops::DerefMut for InputWithMetadata<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.input
    }
}

impl<T: FuzzInput> InputWithMetadata<T> {
    /// Create an [`InputWithMetadata`] with empty metadata
    pub fn from_input(input: T) -> Self {
        Self {
            input,
            metadata: RwLock::new(InputMetadata {
                original_file: 0,
                mutations: Vec::new(),
                new_coverage: Vec::new(),
                entropy: false,
            }),
        }
    }

    /// Read an input from an input's path
    pub fn from_path(input_path: &Path, project_dir: &Path) -> Result<Self> {
        let input = T::from_bytes(&std::fs::read(input_path)?)?;
        let filename = crate::utils::hexdigest(&input);

        let metadata_path = project_dir.join("metadata").join(filename);

        let metadata = if metadata_path.exists() {
            let data = std::fs::read_to_string(metadata_path)?;
            serde_json::from_str(&data)?
        } else {
            InputMetadata::default()
        };

        Ok(Self {
            input,
            metadata: RwLock::new(metadata),
        })
    }

    /// Create a clone of this input with empty metadata and as the original input
    /// as the parent
    pub fn fork(&self) -> Self {
        Self {
            input: self.input.clone(),
            metadata: RwLock::new(InputMetadata {
                original_file: crate::utils::calculate_hash(&self),
                mutations: Vec::new(),
                new_coverage: Vec::new(),
                entropy: false,
            }),
        }
    }

    /// Serialize the input as bytes
    pub fn input_as_bytes(&self) -> Result<Vec<u8>> {
        let mut input_bytes: Vec<u8> = vec![];
        self.input.to_bytes(&mut input_bytes)?;
        Ok(input_bytes)
    }

    /// Serialize the metadata as json
    pub fn serialized_metadata(&self) -> Result<String> {
        let data = self.metadata.read().unwrap();
        Ok(serde_json::to_string(&*data)?)
    }

    /// Get the fuzz_hash of the underlying input
    pub fn fuzz_hash(&self) -> u64 {
        self.input.fuzz_hash()
    }

    /// Set the new coverage for this input
    pub fn add_new_coverage(&self, mut new_coverage: Vec<FeedbackLog>) {
        self.metadata
            .write()
            .unwrap()
            .new_coverage
            .append(&mut new_coverage);
    }

    /// Add the given mutation to this metadata
    pub fn add_mutation(&self, new_mutation: impl Into<String>) {
        self.metadata
            .write()
            .unwrap()
            .mutations
            .push(new_mutation.into());
    }
}
