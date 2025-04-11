use alloc::{string::String, vec::Vec};

pub type TracePipe = TracePipeBuf;

/// TracePipeBuf is a buffer for storing trace records.
///
/// It has a maximum size and can store multiple records.
/// When the buffer is full, it will remove the oldest records to make space for new ones.
/// It is used to store trace records in a ring buffer-like structure.
/// The buffer is implemented as a vector of strings.
pub struct TracePipeBuf {
    size: usize,
    max_record: usize,
    buf: Vec<String>,
}

impl TracePipeBuf {
    pub const fn new(max_record: usize) -> Self {
        Self {
            max_record,
            size: 0,
            buf: Vec::new(),
        }
    }

    fn push_str(&mut self, record: String) {
        let record_size = record.len();
        if self.size + record_size > self.max_record {
            let mut i = 0;
            while i < record_size {
                let t = self.buf.pop().unwrap();
                self.size -= t.len();
                i += t.len();
            }
        }
        self.buf.push(record);
        self.size += record_size;
    }

    /// Read the trace records from the buffer.
    pub fn read_at(&self, buf: &mut [u8], offset: usize) -> Result<usize, &'static str> {
        if offset == self.size {
            return Ok(0);
        }
        if buf.len() < self.size {
            return Err("Buffer too small");
        }
        let mut count = 0;
        for line in self.buf.iter() {
            let line = line.as_bytes();
            buf[count..count + line.len()].copy_from_slice(line);
            count += line.len();
        }
        Ok(count)
    }
}

impl TracePipe {
    /// push a record to the trace pipe.
    pub fn push_record(&mut self, record: String) {
        self.push_str(record);
    }
}
