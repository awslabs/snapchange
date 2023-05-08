//! Provides [`CoverageAnalysis`] to help discover stuck locations in coverage
//!
//! This module takes in a set of basic blocks and metadata about each basic block. When
//! given a set of basic blocks which have already been hit, [`CoverageAnalysis`] will
//! provide a set of basic blocks along with how many potential basic blocks could be
//! covered if the given basic block was hit in the future.
//!
//! This information is primarily used to help a researcher manually trigger potential
//! blockage points in a fuzzer or to help understand what mutations the fuzzer needs to
//! improve on in order to uncover more of the basic blocks in the fuzz run.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::addrs::VirtAddr;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

/// Dump the scores of each basic block to the given file on each update. Used primarily
/// for writing the scores in a disassembler for a check that the analysis is working as
/// expected.
///
/// Can populate a Binary Ninja database using the following:
///
/// ```python
/// raw_scores_file = '/tmp/scores'
/// data = open(raw_scores_file, 'r').read().split('\n')
/// data = [x.split() for x in data]
/// scores = [(int(x[0], 16), int(x[1])) for x in data if len(x) > 1]
/// [bv.set_comment_at(x[0], f'Score {x[1]}') for x in scores]
/// ```
const DUMP_RAW_SCORES: Option<&'static str> = None;

/// A basic block mode metadata. This data is read from the output of the
/// [`bn_snapchange.py`] Binary Ninja plugin.
#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    /// Address of this basic block node
    address: u64,

    /// Addresses of the children (outgoing edges) from this basic block
    children: Vec<u64>,

    /// Addresses of basic blocks that must travel through this basic block to be reached
    dominator_tree_children: Vec<u64>,

    /// Addresses of all parents (incoming_edges) for this basic block
    parents: Vec<u64>,

    /// The name of the function containing this basic block
    function: String,

    /// Offset from the beginning of the function to this basic block
    function_offset: i64,

    /// Function addresses that are called in this basic block node. The score of each
    /// called function is added to the score for this basic block after all nodes are
    /// updated.
    called_funcs: Vec<u64>,

    /// The addresses of the basic blocks that must be hit in order to reach this basic
    /// block. This is used simplify the `best_options` function by ensuring an unhit
    /// block doesn't have dominators in the best options
    dominators: Vec<u64>,
}

/// All basic block nodes.This data is read from the output of the
/// [`./utils/binja_coverage_analysis.py`] utility
#[derive(Serialize, Deserialize, Debug)]
pub struct Nodes {
    /// All known basic block nodes
    nodes: Vec<Node>,
}

/// Provides a list of basic block along with the number of uncovered basic blocks under
/// each basic block to help a researcher understand more about their coverage data
#[derive(Serialize, Deserialize, Default)]
pub struct CoverageAnalysis {
    /// All known basic blocks
    nodes: Vec<Node>,

    /// Lookup table of basic block address to index into `nodes`
    lookup: BTreeMap<u64, usize>,

    /// The number of uncovered basic blocks reachable from this basic block, indexed by
    /// the index into `nodes`
    scores: Vec<usize>,

    /// The list of reachable nodes from basic block index
    reachable_nodes: Vec<BTreeSet<usize>>,

    /// Lookup table of basic block address to all blocks that can trigger this block
    address_called_by: BTreeMap<usize, BTreeSet<usize>>,

    /// The called function node indexes for each basic block
    called_func_indexes: Vec<Option<Vec<usize>>>,

    /// This node has been hit
    hits: Vec<bool>,

    /// The dominator tree children indexes for this node
    dominator_tree_childrens: Vec<Vec<usize>>,

    /// Cached order of nodes to analyze such that each child of a node is analyzed
    /// before the parent. This is to avoid having to re-calculate this order on each
    /// update step. Because the graph of nodes never changes, this caching helps
    /// expediate the analysis.
    cached_order: Option<Vec<usize>>,

    /// Only update the scores of the nodes after nodes have been hit
    update_needed: bool,

    /// Currently cached results for the current best options. This is only updated once
    /// nodes have been hit
    cached_results: Vec<(usize, VirtAddr)>,
}

impl CoverageAnalysis {
    /// Read in the JSON coverage analysis file from Binary Ninja
    pub fn from_binary_ninja(path: &Path) -> Result<CoverageAnalysis> {
        let data = std::fs::read_to_string(path)?;

        // Get all the nodes from the coverage analysis
        let nodes: Vec<Node> = serde_json::from_str(&data).unwrap();

        // Create the `CoverageAnalysis` from the parsed nodes
        Ok(CoverageAnalysis::new(nodes))
    }

    /// Save the current [`CoverageAnalysis`] state to the given `save_path`
    pub fn save_state(&self, save_path: &Path) -> Result<()> {
        log::info!("Saving coverage analysis state to {save_path:?}");

        let start = std::time::Instant::now();

        // Serialize and write the data to the `save_path`
        let data = serde_json::to_string(self)?;
        std::fs::write(save_path, data)?;

        log::info!("Saving coverage analysis state took {:?}", start.elapsed());

        // Return success
        Ok(())
    }

    /// Load the [`CoverageAnalysis`] state from the given `load_path`
    pub fn load_state(load_path: &Path) -> Result<CoverageAnalysis> {
        log::info!("Loading coverage analysis state to {load_path:?}");

        let start = std::time::Instant::now();

        // Serialize and write the data to the `save_path`
        let data = std::fs::read_to_string(load_path)?;
        let state: CoverageAnalysis = serde_json::from_str(&data)?;

        log::info!("Loading coverage analysis state took {:?}", start.elapsed());

        // Return success
        Ok(state)
    }

    /// Initialize an empty coverage analysis.
    ///
    /// Provides an initial empty analysis along with caching the order of nodes
    /// which should be iterated in the future to help performance.
    /// order
    pub fn new(nodes: Vec<Node>) -> Self {
        let mut reachable_nodes = Vec::new();
        for _ in 0..nodes.len() {
            reachable_nodes.push(BTreeSet::new());
        }

        let mut cov_analysis = Self {
            scores: vec![0; nodes.len()],
            reachable_nodes,
            nodes,
            update_needed: true,
            ..Default::default()
        };

        // Create the list of leaf nodes
        for (i, node) in cov_analysis.nodes.iter_mut().enumerate() {
            // Add the current node to the lookup table by address
            cov_analysis.lookup.insert(node.address, i);

            // Add an empty called functions placeholder until we know there are called
            // functions from this node
            cov_analysis.called_func_indexes.push(None);

            // Start this node with not being hit
            cov_analysis.hits.push(false);

            // If a node has children, it is not a leaf node, continue
            if !node.children.is_empty() {
                continue;
            }

            // Found a leaf node, add it to the database
            // cov_analysis.leaf_nodes.push(i);
        }

        // Add the node indexes for each of the called functions
        for (node_index, node) in cov_analysis.nodes.iter().enumerate() {
            for called_func_addr in &node.called_funcs {
                // Get the node index for the called function
                let called_func_index =
                    cov_analysis
                        .lookup
                        .get(called_func_addr)
                        .unwrap_or_else(|| {
                            panic!(
                                "Unknown function found in node {:#x}: {called_func_addr:#x}",
                                node.address
                            )
                        });

                // Allocate a vec if this is the first time seeing a called function from
                // this basic block
                if cov_analysis.called_func_indexes[node_index].is_none() {
                    cov_analysis.called_func_indexes[node_index] = Some(Vec::new());
                }

                // Add the index of the called function to this node's metadata
                if let Some(ref mut curr_funcs) = cov_analysis.called_func_indexes[node_index] {
                    curr_funcs.push(*called_func_index);
                }
            }

            // Create the cache of tree children indexes for this node
            let mut tree_children = Vec::new();
            for child_address in &node.dominator_tree_children {
                if let Some(child_index) = cov_analysis.lookup.get(child_address) {
                    tree_children.push(*child_index);
                }
            }

            // Add the called functions of this block to the list of blocks to add to the
            // score for this block
            for called_func_addr in &node.called_funcs {
                if let Some(child_index) = cov_analysis.lookup.get(called_func_addr) {
                    tree_children.push(*child_index);
                }
            }

            cov_analysis.dominator_tree_childrens.push(tree_children);
        }

        // Perform an initial constructing of the graph of all nodes
        log::info!("Depth-first search population start");
        let start = std::time::Instant::now();
        cov_analysis.depth_first_search();
        log::info!(
            "Depth-first search population took {:?} for {} nodes",
            start.elapsed(),
            cov_analysis.nodes.len()
        );
        // cov_analysis.leaf_nodes.len());

        // Return the initialized coverage analysis
        cov_analysis
    }

    /// Perform a depth-first search over the nodes to find all nodes reachable from any
    /// other node.
    fn depth_first_search(&mut self) {
        let mut work = VecDeque::new();
        let mut seen = BTreeSet::new();

        for curr_node_index in 0..self.nodes.len() {
            // Reset the re-usable alloations for already seen set and current work queue
            seen.clear();
            work.clear();

            // Initialize the work queue for this node
            work.push_front(curr_node_index);

            // Start the reachable nodes with the current node
            self.reachable_nodes[curr_node_index].clear();
            self.reachable_nodes[curr_node_index].insert(curr_node_index);
            seen.insert(curr_node_index);

            // Traverse the directed graph of dominator tree children
            while let Some(new_index) = work.pop_front() {
                for child_index in &self.dominator_tree_childrens[new_index] {
                    // If we have not visited this child node from the current node, add
                    // it to the score and then add the child to work queue to traverse
                    // later
                    if seen.insert(*child_index) {
                        // Only add to the score for this node if the node has not been
                        // hit already
                        self.reachable_nodes[curr_node_index].insert(*child_index);
                        work.push_back(*child_index);

                        // Add this child node to the lookup table to remove if this
                        // child node is hit
                        self.address_called_by
                            .entry(*child_index)
                            .or_default()
                            .insert(curr_node_index);
                    }
                }
            }
        }
    }

    /// Set the node with `address` as being hit
    pub fn hit(&mut self, address: u64) {
        if let Some(index) = self.lookup.get(&address) {
            if self.hits[*index] {
                return;
            }

            self.hits[*index] = true;

            // Signal to `best_options` to recalculate the node scores
            self.update_needed = true;

            // Remove this node from all nodes that have this node as a child
            if let Some(nodes) = self.address_called_by.get(index) {
                for node in nodes {
                    self.reachable_nodes[*node].remove(index);
                }
            }
        }
    }

    /// Get the nodes sorted by best current score. The score for each node is the score
    /// of all of its unhit children nodes.
    pub fn best_options(&mut self) -> &Vec<(usize, VirtAddr)> {
        // If there are no updates needed, return the current cached results
        if !self.update_needed && !self.cached_results.is_empty() {
            return &self.cached_results;
        }

        let mut all_scores = Vec::new();

        let mut seen = BTreeSet::new();

        // Each node is scored based on the score of each of its unhit children
        for node_index in 0..self.nodes.len() {
            // Get the address of the current node
            let addr = self.nodes[node_index].address;

            let mut score = 0;

            // Accumulate the scores for all unhit-children nodes
            for child_address in &self.nodes[node_index].children {
                if let Some(child_index) = self.lookup.get(child_address) {
                    if !self.hits[*child_index] {
                        score += self.reachable_nodes[*child_index].len();
                    }
                }
            }

            // No need to add a node with a score of 0
            if score == 0 {
                continue;
            }

            // Add this score to the list of all current scores
            all_scores.push((score, (VirtAddr(addr), node_index)));
        }

        // Sort the calculated scores by the score value
        all_scores.sort();
        all_scores.reverse();

        // Reset the cached results to be re-populated
        self.cached_results.clear();

        // With all_scores being sorted by score, add each node and then remove all
        // nodes under the added node. This will prevent the results being populated by
        // all nodes from the same path.
        for (score, (addr, node_index)) in &all_scores {
            // Ignore nodes that have been seen before from other nodes
            if !seen.insert(*node_index) {
                continue;
            }

            // Found a good candidate! Add each of its reachable nodes to the seen
            // set to ignore them later since this node's score contains those nodes
            for node in &self.reachable_nodes[*node_index] {
                seen.insert(*node);
            }

            // Found a new result, add it!
            self.cached_results.push((*score, *addr));
        }

        if let Some(outfile) = DUMP_RAW_SCORES {
            let mut res = String::new();
            let mut dot = "digraph nodes {\n".to_string();
            for (score, (addr, _node_index)) in &all_scores {
                let addr = addr.0;
                res.push_str(&format!("{addr:#x} {score}\n"));
                dot.push_str(&format!(
                    "\"{addr:x}\" [label=\"{addr:#x} Scores {score}\"];\n"
                ));
            }

            if std::fs::write(outfile, res).is_err() {
                log::warn!("Failed to write coverage analysis scores to {outfile}");
            }

            for loop_index in 0..self.nodes.len() {
                let addr = self.nodes[loop_index].address;

                for child_index in &self.dominator_tree_childrens[loop_index] {
                    let child_addr = self.nodes[*child_index].address;
                    dot.push_str(&format!("\"{addr:x}\" -> \"{child_addr:x}\";\n"));
                }
            }
            dot.push_str("}\n");

            if std::fs::write("/tmp/graph.dot", dot).is_err() {
                log::error!("Failed to write /tmp/graph.dot");
            }
        }

        // Results have been updated
        self.update_needed = false;

        // Return the best scores
        &self.cached_results
    }
}
