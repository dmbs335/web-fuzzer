//! Native acceleration for webfuzzer hot paths.
//!
//! Provides Rust implementations of performance-critical operations:
//!   - bitmap_has_new_bits : AFL-style coverage bitmap comparison (~200x faster)
//!   - bitmap_update       : Merge bitmaps, return new edge indices
//!   - bitmap_count        : Count non-zero entries in bitmap
//!   - feature_set_bitmap  : SHA-256 feature hashing for coverage
//!   - entropic_compute    : Batch entropy-based energy computation
//!   - havoc_mutate        : AFL-style byte-level mutation chain

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyDict, PyList, PySet};
use sha2::{Digest, Sha256};

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
    Ok(())
}
