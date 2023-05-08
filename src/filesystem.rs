//! An emulated filesystem used to emulate file reads in a
//! [`FuzzVm`](crate::fuzzvm::FuzzVm)

#![allow(dead_code)]

use crate::linux::Whence;
use std::collections::BTreeMap;

/// Possible errors for this emulated file system
#[allow(dead_code)]
#[derive(Debug)]
pub enum Error {
    /// Given an invalid file descriptor
    FileDescriptor,

    /// Received an invalid internal index
    InternalIndex,

    /// Calculated an invalid length for a data slice
    SliceLength,
}

/// The return type encapsulating the [`Error`] for this module
#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, Error>;

/// Emulated filesystem used to perform file operations based on a file descriptor
#[allow(dead_code)]
#[derive(Default, Debug)]
pub struct FileSystem {
    /// Filenames of available files
    names: Vec<String>,

    /// Data of all available files
    data: Vec<Vec<u8>>,

    /// Current offsets of all available files
    offsets: Vec<usize>,

    /// Translation of file descriptors to the internal index
    fd_to_index: BTreeMap<u64, usize>,

    /// The next fd to assign
    next_custom_fd: u64,
}

impl FileSystem {
    /// Add a new file with descriptor `fd`, `name`, and `data` to the filesystem
    pub fn new_file(&mut self, mut fd: Option<u64>, name: String, data: Vec<u8>) {
        if fd.is_none() {
            fd = Some(self.next_custom_fd);
            self.next_custom_fd += 1;
        }

        let fd = fd.unwrap();

        log::debug!("New file! fd: {fd:x?} name: {name:?}");
        // crate::utils::hexdump(&data, 0x12340000);

        // Get the index for the new file
        let index = self.fd_to_index.len();

        if let Some(old_index) = self.fd_to_index.insert(fd, index) {
            log::debug!(
                "Overwritting old file data: fd {fd:#x?} name: {:?} data: {} new data: {}",
                self.names[old_index],
                self.data[old_index].len(),
                data.len()
            );

            // Reset the old_index for this fd
            self.fd_to_index.insert(fd, old_index);

            // Re-using another file descriptor
            self.names[old_index] = name;
            self.data[old_index] = data;
            self.offsets[old_index] = 0;
        } else {
            // Add the new file information to the file system
            self.names.push(name);
            self.data.push(data);
            self.offsets.push(0);
        }
    }

    /// Get the internal index for this file desscriptor
    fn _get_index(&self, fd: u64) -> Result<usize> {
        Ok(*self.fd_to_index.get(&fd).ok_or(Error::FileDescriptor)?)
    }

    /// Read `count` bytes from the file at descriptor `fd`
    pub fn read(&mut self, fd: u64, count: usize) -> Result<&[u8]> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get(index).ok_or(Error::InternalIndex)?;

        // If the offset is already past the total data, return an empty slice
        if *curr_offset > curr_data.len() {
            return Ok(&[]);
        }

        // Calculate the of the slice to read, truncating at the end of the file data
        let end = std::cmp::min(curr_data.len(), *curr_offset + count);

        // Get the returning slice of data
        let data = curr_data.get(*curr_offset..end).ok_or(Error::SliceLength)?;

        log::debug!(
            "Reading stream {fd:#x} from file: {:?}",
            self.names.get(index).ok_or(Error::InternalIndex)?
        );

        // Calculate the length of the data, truncated to the end of the file
        let size = data.len();

        // Update the file offset for this file
        *curr_offset += size;

        // Return the data slice
        Ok(data)
    }

    /// Set the file offset whose descriptor is `fd` using `offset` and [`Whence`]. The
    /// new offset, measured in bytes, is obtained by adding `offset` bytes to the
    /// position specified by [`Whence`].
    ///
    /// Returns the calculated offset
    #[allow(clippy::cast_sign_loss)]
    pub fn seek(&mut self, fd: u64, offset: i32, whence: Whence) -> Result<usize> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        match whence {
            Whence::Set => *curr_offset = offset as usize,
            Whence::Current => *curr_offset = curr_offset.wrapping_add(offset as usize),
            Whence::End => {
                // Get the returning slice of data
                let data = self.data.get(index).ok_or(Error::SliceLength)?;
                let data_len = data.len();
                *curr_offset = data_len.wrapping_add(offset as usize);
            }
            Whence::Unknown(x) => {
                log::warn!("Cannot seek with Unknown whence: {x:?}");
            }
        }

        // Return the new offset
        Ok(*curr_offset)
    }

    /// Get the current data from `stream`
    pub fn get(&mut self, fd: u64) -> Result<&[u8]> {
        log::debug!("Getting file: {fd:#x}");

        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get(index).ok_or(Error::InternalIndex)?;

        // Get the returning slice of data
        curr_data.get(*curr_offset..).ok_or(Error::SliceLength)
    }

    /// Get the current data from `stream`
    pub fn close(&mut self, fd: u64) -> Result<()> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        let curr_data = self.data.get_mut(index).ok_or(Error::InternalIndex)?;

        log::debug!(
            "Closing file: {:?}",
            self.names.get(index).ok_or(Error::InternalIndex)?
        );

        // Clear the data for the closed file
        curr_data.clear();

        Ok(())
    }

    /// Put `byte` into the file at descriptor `fd`
    pub fn ungetc(&mut self, fd: u64, byte: u8) -> Result<()> {
        // Get the internal index for this file desscriptor
        let index = self._get_index(fd)?;

        // Get the current data and offset for the found index
        let curr_offset: &mut usize = self.offsets.get_mut(index).ok_or(Error::InternalIndex)?;

        let curr_data = self.data.get_mut(index).ok_or(Error::InternalIndex)?;

        // Insert the byte into the data for thsi file
        (*curr_data).insert(*curr_offset, byte);

        // Update the file offset for this file
        *curr_offset += 1;

        // Return the data slice
        Ok(())
    }
}
