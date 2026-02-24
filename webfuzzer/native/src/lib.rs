//! Native acceleration for webfuzzer hot paths.
//!
//! Provides Rust implementations of performance-critical operations:
//!   - bitmap_has_new_bits      : AFL-style coverage bitmap comparison (~200x faster)
//!   - bitmap_update            : Merge bitmaps, return new edge indices
//!   - bitmap_count             : Count non-zero entries in bitmap
//!   - feature_set_bitmap       : SHA-256 feature hashing for coverage
//!   - entropic_compute         : Batch entropy-based energy computation
//!   - havoc_mutate             : AFL-style byte-level mutation chain
//!   - parallel_pipe_execute    : GIL-free parallel pipe I/O for persistent targets

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PySet};
use sha2::{Digest, Sha256};

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::mem::ManuallyDrop;
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, RawFd};

// ── AFL hit-count bucket table ─────────────────────────────────
//
// _bucket(0) is special-cased to 0 (not hit).
// For n >= 1: first bucket b in [1,2,3,4,8,16,32,128] where n < b.

const BUCKET: [u8; 256] = {
    let mut table = [128u8; 256];
    table[0] = 0; // special: "not hit"
    table[1] = 2;
    table[2] = 3;
    table[3] = 4;
    // 4..=7 → 8
    let mut i = 4;
    while i <= 7 {
        table[i] = 8;
        i += 1;
    }
    // 8..=15 → 16
    i = 8;
    while i <= 15 {
        table[i] = 16;
        i += 1;
    }
    // 16..=31 → 32
    i = 16;
    while i <= 31 {
        table[i] = 32;
        i += 1;
    }
    // 32..=255 → 128  (already set by default)
    table
};

// ── bitmap_has_new_bits ────────────────────────────────────────

/// Check if `other` bitmap contains any edge not in `self`,
/// or any edge whose AFL bucket class differs.
///
/// Processes 8 bytes at a time for fast early-exit on sparse bitmaps.
#[pyfunction]
fn bitmap_has_new_bits(
    self_bm: &Bound<'_, PyByteArray>,
    other_bm: &Bound<'_, PyByteArray>,
) -> PyResult<bool> {
    // SAFETY: read-only access, GIL held, no Python calls during borrow.
    let self_bytes = unsafe { self_bm.as_bytes() };
    let other_bytes = unsafe { other_bm.as_bytes() };

    if self_bytes.len() != other_bytes.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "bitmap sizes must match",
        ));
    }

    // Phase 1: 8-byte-wide scan for entirely new edges
    let chunks_s = self_bytes.chunks_exact(8);
    let chunks_o = other_bytes.chunks_exact(8);
    let rem_s = chunks_s.remainder();
    let rem_o = chunks_o.remainder();

    for (s8, o8) in chunks_s.zip(chunks_o) {
        let sw = u64::from_le_bytes(s8.try_into().unwrap());
        let ow = u64::from_le_bytes(o8.try_into().unwrap());
        if ow == 0 {
            continue;
        }
        // other has bits where self is zero → new edge
        if ow & !sw != 0 {
            return Ok(true);
        }
    }

    // Phase 2: per-byte bucket comparison (only for non-zero overlapping)
    for (s, o) in self_bytes.iter().zip(other_bytes.iter()) {
        if *o != 0 && *s != 0 && BUCKET[*o as usize] != BUCKET[*s as usize] {
            return Ok(true);
        }
    }

    // Remainder bytes (if len not multiple of 8)
    for (s, o) in rem_s.iter().zip(rem_o.iter()) {
        if *o != 0 && (*s == 0 || BUCKET[*o as usize] != BUCKET[*s as usize]) {
            return Ok(true);
        }
    }

    Ok(false)
}

// ── bitmap_update ──────────────────────────────────────────────

/// Merge `other` into `self_bm` (in-place max).
/// Returns `(set_of_new_edge_indices, edge_count)`.
#[pyfunction]
fn bitmap_update(
    py: Python<'_>,
    self_bm: &Bound<'_, PyByteArray>,
    other_bm: &Bound<'_, PyByteArray>,
) -> PyResult<(Py<PySet>, i32)> {
    // SAFETY: We hold the GIL (py) and no other Python code runs during this block.
    // other_bytes is read-only; bm is mutable. They are distinct Python objects.
    let other_bytes = unsafe { other_bm.as_bytes() };
    let bm = unsafe { self_bm.as_bytes_mut() };

    if bm.len() != other_bytes.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "bitmap sizes must match",
        ));
    }

    let mut new_edges_vec: Vec<usize> = Vec::new();
    let mut edge_count: i32 = 0;

    for i in 0..bm.len() {
        if other_bytes[i] != 0 {
            let old_b = BUCKET[bm[i] as usize];
            let new_b = BUCKET[other_bytes[i] as usize];
            if old_b != new_b {
                new_edges_vec.push(i);
            }
            if other_bytes[i] > bm[i] {
                bm[i] = other_bytes[i];
            }
        }
        if bm[i] != 0 {
            edge_count += 1;
        }
    }

    let set = PySet::new(py, &new_edges_vec)?;
    Ok((set.into(), edge_count))
}

// ── bitmap_count ───────────────────────────────────────────────

/// Count non-zero entries in bitmap.
#[pyfunction]
fn bitmap_count(buf: &Bound<'_, PyByteArray>) -> i32 {
    // SAFETY: read-only, GIL held.
    let bytes = unsafe { buf.as_bytes() };
    bytes.iter().filter(|&&b| b != 0).count() as i32
}

// ── feature_hash_index ─────────────────────────────────────────

/// SHA-256 hash a key string and return bitmap index.
///
/// idx = little_endian(digest[0..2]) % map_size
#[pyfunction]
fn feature_hash_index(key: &str, map_size: i32) -> PyResult<i32> {
    if map_size <= 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "map_size must be positive",
        ));
    }
    let digest = Sha256::digest(key.as_bytes());
    let idx = (digest[0] as i32 | ((digest[1] as i32) << 8)) % map_size;
    Ok(idx)
}

// ── feature_set_bitmap ─────────────────────────────────────────

/// Hash a feature (namespace:value) and increment the bitmap slot.
#[pyfunction]
fn feature_set_bitmap(
    bitmap: &Bound<'_, PyByteArray>,
    namespace: &str,
    value: &str,
    map_size: i32,
) -> PyResult<()> {
    // SAFETY: We hold the GIL and no other Python code runs during this block.
    let bm = unsafe { bitmap.as_bytes_mut() };

    if map_size <= 0 || bm.len() < map_size as usize {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "invalid map_size or bitmap too small",
        ));
    }

    let key = format!("{}:{}", namespace, value);
    let digest = Sha256::digest(key.as_bytes());
    let idx = ((digest[0] as usize) | ((digest[1] as usize) << 8)) % (map_size as usize);

    if bm[idx] < 255 {
        bm[idx] += 1;
    }
    Ok(())
}

// ── entropic_compute ───────────────────────────────────────────

/// Batch-compute entropy-based energy for all seeds.
///
/// feature_sets: list of (set[int] | None) — one per seed
/// edge_freq:    dict[int, int]
/// total_seeds:  int
/// theta:        int (abundance threshold)
/// base_energy:  float
///
/// Returns list of energy values.
#[pyfunction]
fn entropic_compute(
    py: Python<'_>,
    feature_sets: &Bound<'_, PyList>,
    edge_freq: &Bound<'_, PyDict>,
    total_seeds: i32,
    theta: i32,
    base_energy: f64,
) -> PyResult<Py<PyList>> {
    let n_seeds = feature_sets.len();
    let inv_total: f64 = 1.0 / total_seeds as f64;

    let result = PyList::empty(py);

    for i in 0..n_seeds {
        let fset = feature_sets.get_item(i)?;

        // Check if None or empty set
        if fset.is_none()
            || fset.downcast::<PySet>().map_or(true, |s| s.len() == 0)
        {
            result.append(base_energy)?;
            continue;
        }

        let set = fset.downcast::<PySet>()?;
        let mut entropy: f64 = 0.0;

        for item in set.iter() {
            let freq: i32 = match edge_freq.get_item(&item)? {
                Some(v) => v.extract()?,
                None => 1,
            };

            if freq >= theta {
                continue;
            }

            let p = freq as f64 * inv_total;
            if p > 0.0 {
                entropy -= p.log2();
            }
        }

        let energy = (entropy * base_energy).max(0.01);
        result.append(energy)?;
    }

    Ok(result.into())
}

// ── havoc_mutate ───────────────────────────────────────────────

/// AFL interesting values
const INTERESTING_8: [i8; 9] = [0, 1, 16, 32, 64, 100, 127, -128, -1];
const INTERESTING_16: [i16; 11] = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, -32768, -1];
const INTERESTING_32: [i32; 9] = [
    0, 1, 32768, 65535, 65536, 100663045, 2147483647, -2147483648, -1,
];

/// xorshift128+ PRNG
struct Xor128 {
    s0: u64,
    s1: u64,
}

impl Xor128 {
    fn new(seed: u64) -> Self {
        Xor128 {
            s0: seed | 1,
            s1: ((seed >> 32) ^ 0xDEAD_BEEF_CAFE) | 1,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut s1 = self.s0;
        let s0 = self.s1;
        self.s0 = s0;
        s1 ^= s1 << 23;
        s1 ^= s1 >> 17;
        s1 ^= s0;
        s1 ^= s0 >> 26;
        self.s1 = s1;
        self.s0.wrapping_add(self.s1)
    }

    fn randint(&mut self, lo: i32, hi: i32) -> i32 {
        if lo >= hi {
            return lo;
        }
        let range = (hi - lo + 1) as u64;
        lo + (self.next_u64() % range) as i32
    }
}

/// Apply a batch of AFL-style havoc mutations.
///
/// Uses xorshift128+ PRNG. Op 13 (corpus splice) is mapped to op 12 (clone).
#[pyfunction]
fn havoc_mutate(data: &[u8], num_ops: i32, seed: u64) -> PyResult<Vec<u8>> {
    if data.is_empty() {
        return Ok(data.to_vec());
    }

    let max_len: usize = (data.len() * 2).clamp(256, 1 << 20);
    let mut buf = Vec::with_capacity(max_len);
    buf.extend_from_slice(data);

    let mut rng = Xor128::new(seed);

    for _ in 0..num_ops {
        let len = buf.len();
        if len == 0 {
            break;
        }
        let op = rng.randint(0, 13);

        match op {
            0 => {
                // bit flip
                let pos = rng.randint(0, len as i32 - 1) as usize;
                let bit = rng.randint(0, 7);
                buf[pos] ^= 1u8 << bit;
            }
            1 => {
                // byte flip
                let pos = rng.randint(0, len as i32 - 1) as usize;
                buf[pos] ^= 0xFF;
            }
            2 => {
                // random byte
                let pos = rng.randint(0, len as i32 - 1) as usize;
                buf[pos] = rng.randint(0, 255) as u8;
            }
            3 => {
                // arithmetic 8-bit
                let pos = rng.randint(0, len as i32 - 1) as usize;
                let delta = rng.randint(1, 35) as u8;
                if rng.next_u64() & 1 != 0 {
                    buf[pos] = buf[pos].wrapping_add(delta);
                } else {
                    buf[pos] = buf[pos].wrapping_sub(delta);
                }
            }
            4 => {
                // arithmetic 16-bit
                if len >= 2 {
                    let pos = rng.randint(0, len as i32 - 2) as usize;
                    let mut val = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
                    let delta = rng.randint(1, 35) as u16;
                    if rng.next_u64() & 1 != 0 {
                        val = val.wrapping_add(delta);
                    } else {
                        val = val.wrapping_sub(delta);
                    }
                    let bytes = val.to_le_bytes();
                    buf[pos] = bytes[0];
                    buf[pos + 1] = bytes[1];
                }
            }
            5 => {
                // arithmetic 32-bit
                if len >= 4 {
                    let pos = rng.randint(0, len as i32 - 4) as usize;
                    let mut val =
                        u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
                    let delta = rng.randint(1, 35) as u32;
                    if rng.next_u64() & 1 != 0 {
                        val = val.wrapping_add(delta);
                    } else {
                        val = val.wrapping_sub(delta);
                    }
                    let bytes = val.to_le_bytes();
                    buf[pos..pos + 4].copy_from_slice(&bytes);
                }
            }
            6 => {
                // interesting 8-bit
                let pos = rng.randint(0, len as i32 - 1) as usize;
                let idx = rng.randint(0, INTERESTING_8.len() as i32 - 1) as usize;
                buf[pos] = INTERESTING_8[idx] as u8;
            }
            7 => {
                // interesting 16-bit
                if len >= 2 {
                    let pos = rng.randint(0, len as i32 - 2) as usize;
                    let idx = rng.randint(0, INTERESTING_16.len() as i32 - 1) as usize;
                    let val = INTERESTING_16[idx] as u16;
                    if rng.next_u64() & 1 != 0 {
                        let bytes = val.to_le_bytes();
                        buf[pos] = bytes[0];
                        buf[pos + 1] = bytes[1];
                    } else {
                        let bytes = val.to_be_bytes();
                        buf[pos] = bytes[0];
                        buf[pos + 1] = bytes[1];
                    }
                }
            }
            8 => {
                // interesting 32-bit
                if len >= 4 {
                    let pos = rng.randint(0, len as i32 - 4) as usize;
                    let idx = rng.randint(0, INTERESTING_32.len() as i32 - 1) as usize;
                    let val = INTERESTING_32[idx] as u32;
                    if rng.next_u64() & 1 != 0 {
                        buf[pos..pos + 4].copy_from_slice(&val.to_le_bytes());
                    } else {
                        buf[pos..pos + 4].copy_from_slice(&val.to_be_bytes());
                    }
                }
            }
            9 => {
                // delete block
                if len > 4 {
                    let max_bl = std::cmp::min(len / 4, 32).max(1);
                    let bl = rng.randint(1, max_bl as i32) as usize;
                    let pos = rng.randint(0, (len - bl) as i32) as usize;
                    buf.drain(pos..pos + bl);
                }
            }
            10 => {
                // insert random block
                let bl = rng.randint(1, 32) as usize;
                if len + bl <= max_len {
                    let pos = rng.randint(0, len as i32) as usize;
                    let block: Vec<u8> = (0..bl).map(|_| rng.randint(0, 255) as u8).collect();
                    buf.splice(pos..pos, block);
                }
            }
            11 => {
                // overwrite random block
                let max_bl = std::cmp::min(16, len).max(1);
                let bl = rng.randint(1, max_bl as i32) as usize;
                let pos = rng.randint(0, (len - bl) as i32) as usize;
                for j in 0..bl {
                    buf[pos + j] = rng.randint(0, 255) as u8;
                }
            }
            12 | 13 => {
                // clone block (13=splice mapped to clone)
                if len > 4 {
                    let max_bl = std::cmp::min(len / 4, 32).max(1);
                    let bl = rng.randint(1, max_bl as i32) as usize;
                    let src = rng.randint(0, (len - bl) as i32) as usize;
                    let dst = rng.randint(0, len as i32) as usize;
                    if len + bl <= max_len {
                        let block: Vec<u8> = buf[src..src + bl].to_vec();
                        buf.splice(dst..dst, block);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(buf)
}

// ── parallel_pipe_execute ──────────────────────────────────────
//
// GIL-free parallel pipe I/O for persistent fuzzing targets.
//
// Eliminates Python threading overhead (15 thread creations/iteration)
// by performing all pipe I/O in native Rust threads with GIL released.
//
// Protocol (big-endian):
//   Request:  [4-byte length][input bytes]
//   Response: [4-byte length][output bytes][4-byte exit_code]

/// Result from a single pipe I/O operation.
struct PipeResult {
    index: usize,
    output: Vec<u8>,
    exit_code: u32,
    duration_ms: f64,
    error: Option<String>,
}

// ── Windows raw pipe I/O (non-blocking reads via PeekNamedPipe) ────
//
// Using raw Win32 APIs instead of File::read() to avoid blocking on
// anonymous pipes when a child process hangs. PeekNamedPipe checks
// data availability without blocking, enabling proper timeout handling.

#[cfg(windows)]
extern "system" {
    fn PeekNamedPipe(
        h: isize, buf: *mut u8, sz: u32,
        read: *mut u32, avail: *mut u32, left: *mut u32,
    ) -> i32;
    fn ReadFile(
        h: isize, buf: *mut u8, to_read: u32,
        read: *mut u32, overlapped: *mut u8,
    ) -> i32;
    fn WriteFile(
        h: isize, buf: *const u8, to_write: u32,
        written: *mut u32, overlapped: *mut u8,
    ) -> i32;
    fn FlushFileBuffers(h: isize) -> i32;
}

/// Write all bytes to a handle (Windows).
#[cfg(windows)]
fn win_write_all(handle: u64, data: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < data.len() {
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(
                handle as isize,
                data[offset..].as_ptr(),
                (data.len() - offset) as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return Err("WriteFile failed".to_string());
        }
        offset += written as usize;
    }
    Ok(())
}

/// Read exactly `n` bytes using PeekNamedPipe (non-blocking) + ReadFile.
/// Never blocks indefinitely — returns timeout error if deadline exceeded.
#[cfg(windows)]
fn win_read_exact(
    handle: u64,
    n: usize,
    start: Instant,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        if start.elapsed() > timeout {
            return Err("timeout".to_string());
        }
        // Check if data available (non-blocking)
        let mut avail: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle as isize,
                std::ptr::null_mut(), 0,
                std::ptr::null_mut(), &mut avail, std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err("EOF: pipe broken".to_string());
        }
        if avail == 0 {
            // No data yet — brief sleep to avoid busy-spin
            thread::sleep(Duration::from_micros(50));
            continue;
        }
        // Read available data (won't block since we confirmed availability)
        let to_read = std::cmp::min((n - filled) as u32, avail);
        let mut read: u32 = 0;
        let ok = unsafe {
            ReadFile(
                handle as isize,
                buf[filled..].as_mut_ptr(),
                to_read,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return Err("EOF: ReadFile failed".to_string());
        }
        filled += read as usize;
    }
    Ok(buf)
}

/// Execute the persistent target binary protocol on one pipe pair.
///
/// On Windows: uses PeekNamedPipe for non-blocking reads (no deadlock).
/// On Unix: uses File::read() (blocking, but pipe EOF works correctly).
fn pipe_execute_one(
    index: usize,
    stdin_handle: u64,
    stdout_handle: u64,
    input: &[u8],
    timeout: Duration,
) -> PipeResult {
    let start = Instant::now();

    // ── Write request ──
    #[cfg(windows)]
    {
        let header = (input.len() as u32).to_be_bytes();
        if let Err(e) = win_write_all(stdin_handle, &header) {
            return PipeResult {
                index, output: Vec::new(), exit_code: u32::MAX,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!("write header: {}", e)),
            };
        }
        if let Err(e) = win_write_all(stdin_handle, input) {
            return PipeResult {
                index, output: Vec::new(), exit_code: u32::MAX,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!("write data: {}", e)),
            };
        }
        unsafe { FlushFileBuffers(stdin_handle as isize); }
    }

    #[cfg(unix)]
    {
        let mut writer = unsafe {
            ManuallyDrop::new(std::fs::File::from_raw_fd(stdin_handle as RawFd))
        };
        let header = (input.len() as u32).to_be_bytes();
        if let Err(e) = writer.write_all(&header) {
            return PipeResult {
                index, output: Vec::new(), exit_code: u32::MAX,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!("write header: {}", e)),
            };
        }
        if let Err(e) = writer.write_all(input) {
            return PipeResult {
                index, output: Vec::new(), exit_code: u32::MAX,
                duration_ms: start.elapsed().as_secs_f64() * 1000.0,
                error: Some(format!("write data: {}", e)),
            };
        }
        let _ = writer.flush();
    }

    // ── Read response ──
    // Helper macro to reduce repetition
    macro_rules! try_read {
        ($n:expr, $start:expr, $timeout:expr) => {{
            #[cfg(windows)]
            let result = win_read_exact(stdout_handle, $n, $start, $timeout);
            #[cfg(unix)]
            let result = {
                let mut reader = unsafe {
                    ManuallyDrop::new(std::fs::File::from_raw_fd(stdout_handle as RawFd))
                };
                let mut buf = vec![0u8; $n];
                let mut filled = 0;
                let mut err = None;
                while filled < $n {
                    if $start.elapsed() > $timeout {
                        err = Some("timeout".to_string());
                        break;
                    }
                    match reader.read(&mut buf[filled..]) {
                        Ok(0) => { err = Some("EOF: process died".to_string()); break; }
                        Ok(k) => filled += k,
                        Err(e) => { err = Some(format!("read error: {}", e)); break; }
                    }
                }
                match err {
                    Some(e) => Err(e),
                    None => Ok(buf),
                }
            };
            result
        }};
    }

    // 1. Read response header: [4-byte BE length]
    let resp_header = match try_read!(4, start, timeout) {
        Ok(h) => h,
        Err(e) => return PipeResult {
            index, output: Vec::new(), exit_code: u32::MAX,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: Some(e),
        },
    };
    let out_len = u32::from_be_bytes([
        resp_header[0], resp_header[1], resp_header[2], resp_header[3],
    ]) as usize;

    // Sanity check: reject > 64 MB outputs
    if out_len > 64 * 1024 * 1024 {
        return PipeResult {
            index, output: Vec::new(), exit_code: u32::MAX,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: Some(format!("output too large: {} bytes", out_len)),
        };
    }

    // 2. Read output bytes
    let output = match try_read!(out_len, start, timeout) {
        Ok(o) => o,
        Err(e) => return PipeResult {
            index, output: Vec::new(), exit_code: u32::MAX,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: Some(e),
        },
    };

    // 3. Read exit code: [4-byte BE]
    let exit_bytes = match try_read!(4, start, timeout) {
        Ok(b) => b,
        Err(e) => return PipeResult {
            index, output, exit_code: u32::MAX,
            duration_ms: start.elapsed().as_secs_f64() * 1000.0,
            error: Some(e),
        },
    };
    let exit_code = u32::from_be_bytes([
        exit_bytes[0], exit_bytes[1], exit_bytes[2], exit_bytes[3],
    ]);

    PipeResult {
        index, output, exit_code,
        duration_ms: start.elapsed().as_secs_f64() * 1000.0,
        error: None,
    }
}

/// Execute input against multiple persistent targets in parallel via raw pipe I/O.
///
/// Releases the GIL and spawns native Rust threads — zero Python threading overhead.
///
/// Args:
///   handles: list of (stdin_handle, stdout_handle) as OS-level integers
///   input_data: bytes to send to each target
///   timeout_ms: per-target timeout in milliseconds
///
/// Returns:
///   list of (output: bytes, exit_code: int, duration_ms: float, error: str | None)
#[pyfunction]
fn parallel_pipe_execute(
    py: Python<'_>,
    handles: Vec<(u64, u64)>,
    input_data: &[u8],
    timeout_ms: u64,
) -> PyResult<Vec<(Py<PyBytes>, u32, f64, Option<String>)>> {
    let n = handles.len();
    if n == 0 {
        return Ok(Vec::new());
    }

    let timeout = Duration::from_millis(timeout_ms);
    let input_owned: Vec<u8> = input_data.to_vec();

    // Release GIL and run all I/O in parallel
    let results = py.allow_threads(|| {
        let (tx, rx) = mpsc::channel::<PipeResult>();

        let mut join_handles = Vec::with_capacity(n);
        for (i, (stdin_h, stdout_h)) in handles.iter().enumerate() {
            let tx = tx.clone();
            let input_clone = input_owned.clone();
            let sh_in = *stdin_h;
            let sh_out = *stdout_h;
            let t = timeout;

            let handle = thread::spawn(move || {
                let result = pipe_execute_one(i, sh_in, sh_out, &input_clone, t);
                let _ = tx.send(result);
            });
            join_handles.push(handle);
        }
        drop(tx);

        // Collect results with overall timeout
        let overall_timeout = timeout + Duration::from_secs(1);
        let collect_start = Instant::now();
        let mut results: Vec<Option<PipeResult>> = (0..n).map(|_| None).collect();
        let mut received = 0;

        while received < n {
            let remaining = overall_timeout
                .checked_sub(collect_start.elapsed())
                .unwrap_or(Duration::ZERO);

            match rx.recv_timeout(remaining) {
                Ok(pr) => {
                    let idx = pr.index;
                    results[idx] = Some(pr);
                    received += 1;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    for slot in results.iter_mut() {
                        if slot.is_none() {
                            *slot = Some(PipeResult {
                                index: 0,
                                output: Vec::new(),
                                exit_code: u32::MAX,
                                duration_ms: timeout.as_secs_f64() * 1000.0,
                                error: Some("overall timeout".to_string()),
                            });
                        }
                    }
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // Only join threads that already completed (sent their result).
        // Threads stuck on a blocking read() will unblock when Python
        // kills the child process (teardown closes the pipe).
        // DO NOT join all — a stuck thread would deadlock us.
        for h in join_handles {
            // Try a brief join; if the thread is stuck, just detach it.
            // Rust threads are detached on drop anyway.
            drop(h);
        }

        results
    });

    // Convert back to Python objects (GIL reacquired)
    let mut py_results = Vec::with_capacity(n);
    for slot in results {
        match slot {
            Some(pr) => {
                let bytes = PyBytes::new(py, &pr.output);
                py_results.push((bytes.into(), pr.exit_code, pr.duration_ms, pr.error));
            }
            None => {
                let bytes = PyBytes::new(py, b"");
                py_results.push((
                    bytes.into(), u32::MAX, 0.0,
                    Some("no result received".to_string()),
                ));
            }
        }
    }

    Ok(py_results)
}

// ── Python module ──────────────────────────────────────────────

#[pymodule]
fn _speedups(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bitmap_has_new_bits, m)?)?;
    m.add_function(wrap_pyfunction!(bitmap_update, m)?)?;
    m.add_function(wrap_pyfunction!(bitmap_count, m)?)?;
    m.add_function(wrap_pyfunction!(feature_hash_index, m)?)?;
    m.add_function(wrap_pyfunction!(feature_set_bitmap, m)?)?;
    m.add_function(wrap_pyfunction!(entropic_compute, m)?)?;
    m.add_function(wrap_pyfunction!(havoc_mutate, m)?)?;
    m.add_function(wrap_pyfunction!(parallel_pipe_execute, m)?)?;
    Ok(())
}
