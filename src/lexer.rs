use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher};

use crate::error::{line_col_at, XmlError, XmlErrorKind};
use crate::{
    Config, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_OUTPUT_BYTES, MAX_DEPTH, MAX_LINT_DIAGNOSTICS,
};

const XML_NS_URI: &[u8] = b"http://www.w3.org/XML/1998/namespace";
const XMLNS_NS_URI: &[u8] = b"http://www.w3.org/2000/xmlns/";

/// Bounded output byte sink that strictly enforces `max_bytes` before copying and caps
/// underlying `Vec<u8>` capacity at `max_bytes` using `try_reserve_exact` (CWE-400).
pub struct BoundedVecRefSink<'a> {
    buf: &'a mut Vec<u8>,
    max_bytes: usize,
}

impl<'a> BoundedVecRefSink<'a> {
    #[inline]
    pub fn new(buf: &'a mut Vec<u8>, max_bytes: usize) -> Self {
        Self { buf, max_bytes }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[inline]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Appends `bytes` to the underlying buffer if `len + bytes.len() <= max_bytes`.
    /// Never allocates capacity beyond `max_bytes`.
    #[inline]
    pub fn write_slice(&mut self, bytes: &[u8]) -> bool {
        let Some(new_len) = self.buf.len().checked_add(bytes.len()) else {
            return false;
        };
        if new_len > self.max_bytes {
            return false;
        }
        if new_len > self.buf.capacity() {
            let doubled = self.buf.capacity().saturating_mul(2).max(64);
            let target_cap = doubled.max(new_len).min(self.max_bytes);
            let additional = target_cap - self.buf.len();
            if self.buf.try_reserve_exact(additional).is_err() {
                return false;
            }
        }
        self.buf.extend_from_slice(bytes);
        true
    }
}

/// Fast non-cryptographic FxHasher used in Tier 2 (`9..=64` entries) of `KeySet`.
#[derive(Default, Clone)]
pub struct FxHasher {
    hash: u64,
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const K: u64 = 0x517cc1b727220a95;
        let mut h = self.hash;
        let mut i = 0;
        while i + 8 <= bytes.len() {
            let word = u64::from_ne_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
                bytes[i + 4],
                bytes[i + 5],
                bytes[i + 6],
                bytes[i + 7],
            ]);
            h = (h.rotate_left(5) ^ word).wrapping_mul(K);
            i += 8;
        }
        while i < bytes.len() {
            h = (h.rotate_left(5) ^ (bytes[i] as u64)).wrapping_mul(K);
            i += 1;
        }
        self.hash = h;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// ASLR-seeded BuildHasher for Tier 2 `FxHasher` (CWE-407).
#[derive(Clone, Copy, Debug)]
pub struct FxBuildHasher {
    seed: u64,
}

impl FxBuildHasher {
    #[inline]
    pub fn new() -> Self {
        let stack_slot = 0u64;
        let stack_addr = &stack_slot as *const u64 as usize as u64;
        let fn_addr = Self::new as *const () as usize as u64;
        let seed = stack_addr
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(fn_addr.rotate_left(17))
            ^ 0x517C_C1B7_2722_0A95;
        Self { seed }
    }
}

impl Default for FxBuildHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for FxBuildHasher {
    type Hasher = FxHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FxHasher { hash: self.seed }
    }
}

/// 3-Tier adaptive uniqueness set:
/// - Tier 1: `Vec<K>` for `<= 8` keys (zero hash overhead, cache-line friendly)
/// - Tier 2: `HashSet<K, FxBuildHasher>` for `9..=64` keys (ASLR-seeded FxHash)
/// - Tier 3: `HashSet<K, RandomState>` (SipHash-1-3) for `> 64` keys (HashDoS immune)
#[derive(Debug, Clone)]
pub enum KeySet<K> {
    Tier1Vec(Vec<K>),
    Tier2Fx(HashSet<K, FxBuildHasher>),
    Tier3Sip(HashSet<K, RandomState>),
}

impl<K: Eq + Hash + Clone> Default for KeySet<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash + Clone> KeySet<K> {
    #[inline]
    pub fn new() -> Self {
        KeySet::Tier1Vec(Vec::with_capacity(8))
    }

    #[inline]
    pub fn clear(&mut self) {
        match self {
            KeySet::Tier1Vec(v) => {
                v.clear();
                if v.capacity() > 8 {
                    v.shrink_to(8);
                }
            }
            KeySet::Tier2Fx(_) | KeySet::Tier3Sip(_) => {
                *self = KeySet::Tier1Vec(Vec::with_capacity(8));
            }
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        match self {
            KeySet::Tier1Vec(v) => v.capacity(),
            KeySet::Tier2Fx(s) => s.capacity(),
            KeySet::Tier3Sip(s) => s.capacity(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            KeySet::Tier1Vec(v) => v.len(),
            KeySet::Tier2Fx(s) => s.len(),
            KeySet::Tier3Sip(s) => s.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn tier(&self) -> u8 {
        match self {
            KeySet::Tier1Vec(_) => 1,
            KeySet::Tier2Fx(_) => 2,
            KeySet::Tier3Sip(_) => 3,
        }
    }

    /// Inserts `key` into the set. Returns `true` if the key was newly inserted,
    /// or `false` if it was already present.
    pub fn insert(&mut self, key: K) -> bool {
        match self {
            KeySet::Tier1Vec(vec) => {
                if vec.contains(&key) {
                    return false;
                }
                if vec.len() < 8 {
                    vec.push(key);
                    return true;
                }
                // Upgrade Tier 1 (8) -> Tier 2 (9..=64) with ASLR-seeded FxBuildHasher
                let mut set = HashSet::with_capacity_and_hasher(16, FxBuildHasher::new());
                for existing in vec.drain(..) {
                    set.insert(existing);
                }
                let inserted = set.insert(key);
                *self = KeySet::Tier2Fx(set);
                inserted
            }
            KeySet::Tier2Fx(set) => {
                if set.contains(&key) {
                    return false;
                }
                if set.len() < 64 {
                    return set.insert(key);
                }
                // Upgrade Tier 2 (64) -> Tier 3 (> 64, SipHash-1-3)
                let mut sip_set = HashSet::with_capacity_and_hasher(128, RandomState::new());
                for existing in set.drain() {
                    sip_set.insert(existing);
                }
                let inserted = sip_set.insert(key);
                *self = KeySet::Tier3Sip(sip_set);
                inserted
            }
            KeySet::Tier3Sip(set) => set.insert(key),
        }
    }
}

/// Type alias for raw attribute QName uniqueness per start tag.
pub type RawKeySet<'a> = KeySet<&'a [u8]>;

/// Type alias for SipHash-protected namespace prefix binding map when a tag declares `> 8` bindings.
pub type NsBindingMap<'a> = HashMap<&'a [u8], Cow<'a, [u8]>, RandomState>;

/// Explicit non-recursive element stack frame.
#[derive(Debug, Clone)]
pub struct XmlFrame<'a> {
    pub raw_name: &'a [u8],
    pub open_offset: usize,
    pub open_line: usize,
    pub open_col: usize,
    pub default_ns: Cow<'a, [u8]>,
    pub ns_bindings: Vec<(&'a [u8], Cow<'a, [u8]>)>,
    pub ns_map: Option<NsBindingMap<'a>>,
    pub xml_space_preserve: bool,
    pub has_child_elements: bool,
    pub has_non_ws_text: bool,
    pub inline_mode: bool,
}

impl<'a> XmlFrame<'a> {
    #[inline]
    pub fn insert_ns_binding(&mut self, prefix: &'a [u8], uri: Cow<'a, [u8]>) {
        if let Some(ref mut map) = self.ns_map {
            map.insert(prefix, uri);
            return;
        }
        self.ns_bindings.push((prefix, uri));
        if self.ns_bindings.len() > 8 {
            let mut map = HashMap::with_capacity_and_hasher(16, RandomState::new());
            for (k, v) in self.ns_bindings.drain(..) {
                map.insert(k, v);
            }
            self.ns_map = Some(map);
        }
    }

    #[inline]
    pub fn get_ns_binding(&self, prefix: &[u8]) -> Option<&Cow<'a, [u8]>> {
        if let Some(ref map) = self.ns_map {
            return map.get(prefix);
        }
        for (p, uri) in self.ns_bindings.iter().rev() {
            if *p == prefix {
                return Some(uri);
            }
        }
        None
    }
}

/// Buffered attribute on a single start or empty-element tag.
#[derive(Debug, Clone)]
struct BufferedAttr<'a> {
    raw_name: &'a [u8],
    prefix: Option<&'a [u8]>,
    local_name: &'a [u8],
    raw_value: &'a [u8],
    quote: u8,
    name_offset: usize,
    value_offset: usize,
}

/// Fast-scans plain ASCII XML character data (`0x20..=0x7E` plus `\t`, `\n`),
/// stopping on `<` (`0x3C`), `&` (`0x26`), `]` (`0x5D`), `\r` (`0x0D`),
/// control bytes `< 0x20` (other than `\t`, `\n`), DEL (`0x7F`), or UTF-8 lead bytes `>= 0x80`.
#[inline]
pub fn skip_xml_text_bytes(bytes: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: CPU support for AVX2 was just verified via `is_x86_feature_detected!("avx2")`,
            // satisfying the `#[target_feature(enable = "avx2")]` precondition.
            return unsafe { skip_xml_text_bytes_avx2(bytes) };
        }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        // SAFETY: `#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]` guarantees
        // NEON/ASIMD support at compile time on this target.
        return unsafe { skip_xml_text_bytes_neon(bytes) };
    }
    #[allow(unreachable_code)]
    skip_xml_text_bytes_swar(bytes)
}

/// Fast-scans plain ASCII XML attribute values (`0x20..=0x7E`),
/// stopping on the active `quote` (`"` or `'`), `<` (`0x3C`), `&` (`0x26`),
/// control bytes `< 0x20`, DEL (`0x7F`), or UTF-8 lead bytes `>= 0x80`.
#[inline]
pub fn skip_xml_attr_bytes(bytes: &[u8], quote: u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: CPU support for AVX2 was just verified via `is_x86_feature_detected!("avx2")`,
            // satisfying the `#[target_feature(enable = "avx2")]` precondition.
            return unsafe { skip_xml_attr_bytes_avx2(bytes, quote) };
        }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        // SAFETY: `#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]` guarantees
        // NEON/ASIMD support at compile time on this target.
        return unsafe { skip_xml_attr_bytes_neon(bytes, quote) };
    }
    #[allow(unreachable_code)]
    skip_xml_attr_bytes_swar(bytes, quote)
}

#[inline]
const fn is_fast_text_byte(b: u8) -> bool {
    (b >= 0x20 && b < 0x7F && b != b'<' && b != b'&' && b != b']') || b == b'\t' || b == b'\n'
}

#[inline]
const fn is_fast_attr_byte(b: u8, quote: u8) -> bool {
    b >= 0x20 && b < 0x7F && b != quote && b != b'<' && b != b'&'
}

/// Portable 8-byte SWAR + scalar scanner for XML text bytes (stops on 0x7F DEL per Ruling 2).
#[inline]
pub fn skip_xml_text_bytes_swar(bytes: &[u8]) -> usize {
    let mut i = 0;
    let len = bytes.len();
    while i + 8 <= len {
        let word = u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ]);
        // Reject any byte >= 0x80 or < 0x20, or equal to '<' (0x3C), '&' (0x26), ']' (0x5D), DEL (0x7F)
        let high_mask = word & 0x8080_8080_8080_8080;
        let lt_20 = word.wrapping_sub(0x2020_2020_2020_2020) & !word & 0x8080_8080_8080_8080;
        let eq_lt = has_zero_byte_u64(word ^ 0x3C3C_3C3C_3C3C_3C3C);
        let eq_amp = has_zero_byte_u64(word ^ 0x2626_2626_2626_2626);
        let eq_rb = has_zero_byte_u64(word ^ 0x5D5D_5D5D_5D5D_5D5D);
        let eq_del = has_zero_byte_u64(word ^ 0x7F7F_7F7F_7F7F_7F7F);
        if (high_mask | lt_20 | eq_lt | eq_amp | eq_rb | eq_del) != 0 {
            for j in 0..8 {
                if !is_fast_text_byte(bytes[i + j]) {
                    return i + j;
                }
            }
        }
        i += 8;
    }
    while i < len && is_fast_text_byte(bytes[i]) {
        i += 1;
    }
    i
}

/// Portable 8-byte SWAR + scalar scanner for XML attribute bytes (stops on 0x7F DEL per Ruling 2).
#[inline]
pub fn skip_xml_attr_bytes_swar(bytes: &[u8], quote: u8) -> usize {
    let mut i = 0;
    let len = bytes.len();
    let quote_splat = (quote as u64) * 0x0101_0101_0101_0101;
    while i + 8 <= len {
        let word = u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ]);
        let high_mask = word & 0x8080_8080_8080_8080;
        let lt_20 = word.wrapping_sub(0x2020_2020_2020_2020) & !word & 0x8080_8080_8080_8080;
        let eq_q = has_zero_byte_u64(word ^ quote_splat);
        let eq_lt = has_zero_byte_u64(word ^ 0x3C3C_3C3C_3C3C_3C3C);
        let eq_amp = has_zero_byte_u64(word ^ 0x2626_2626_2626_2626);
        let eq_del = has_zero_byte_u64(word ^ 0x7F7F_7F7F_7F7F_7F7F);
        let combined = high_mask | lt_20 | eq_q | eq_lt | eq_amp | eq_del;
        if combined != 0 {
            let stop_byte = (combined.trailing_zeros() / 8) as usize;
            return i + stop_byte;
        }
        i += 8;
    }
    while i < len && is_fast_attr_byte(bytes[i], quote) {
        i += 1;
    }
    i
}

#[inline]
const fn has_zero_byte_u64(x: u64) -> u64 {
    x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_xml_text_bytes_avx2(bytes: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let mut i = 0;
    let len = bytes.len();
    let ptr = bytes.as_ptr();

    // SAFETY: Caller guarantees CPU AVX2 availability (via `is_x86_feature_detected!("avx2")`),
    // satisfying the `#[target_feature(enable = "avx2")]` requirement for AVX2 intrinsics.
    // The loop condition `i + 32 <= len` ensures `ptr.add(i)` and the 32-byte unaligned load
    // `_mm256_loadu_si256` always read strictly within `bytes`.
    unsafe {
        let v_lt = _mm256_set1_epi8(b'<' as i8);
        let v_amp = _mm256_set1_epi8(b'&' as i8);
        let v_rb = _mm256_set1_epi8(b']' as i8);
        let v_del = _mm256_set1_epi8(0x7F);
        let v_tab = _mm256_set1_epi8(b'\t' as i8);
        let v_lf = _mm256_set1_epi8(b'\n' as i8);
        let v_space = _mm256_set1_epi8(0x20);

        while i + 32 <= len {
            let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
            // Signed `0x20 > chunk` matches `0x00..=0x1F` (0..=31) and `0x80..=0xFF` (-128..=-1)
            let is_ctrl_or_high = _mm256_cmpgt_epi8(v_space, chunk);
            let is_tab = _mm256_cmpeq_epi8(chunk, v_tab);
            let is_lf = _mm256_cmpeq_epi8(chunk, v_lf);
            let allowed_ws = _mm256_or_si256(is_tab, is_lf);
            let bad_ctrl_or_high = _mm256_andnot_si256(allowed_ws, is_ctrl_or_high);

            let is_lt = _mm256_cmpeq_epi8(chunk, v_lt);
            let is_amp = _mm256_cmpeq_epi8(chunk, v_amp);
            let is_rb = _mm256_cmpeq_epi8(chunk, v_rb);
            let is_del = _mm256_cmpeq_epi8(chunk, v_del);

            let stop_vec = _mm256_or_si256(
                _mm256_or_si256(bad_ctrl_or_high, is_lt),
                _mm256_or_si256(_mm256_or_si256(is_amp, is_rb), is_del),
            );
            let mask = _mm256_movemask_epi8(stop_vec) as u32;
            if mask != 0 {
                return i + mask.trailing_zeros() as usize;
            }
            i += 32;
        }
    }
    i + skip_xml_text_bytes_swar(&bytes[i..])
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_xml_attr_bytes_avx2(bytes: &[u8], quote: u8) -> usize {
    use std::arch::x86_64::*;
    let mut i = 0;
    let len = bytes.len();
    let ptr = bytes.as_ptr();

    // SAFETY: Caller guarantees CPU AVX2 availability (via `is_x86_feature_detected!("avx2")`),
    // satisfying the `#[target_feature(enable = "avx2")]` requirement for AVX2 intrinsics.
    // The loop condition `i + 32 <= len` ensures `ptr.add(i)` and the 32-byte unaligned load
    // `_mm256_loadu_si256` always read strictly within `bytes`.
    unsafe {
        let v_quote = _mm256_set1_epi8(quote as i8);
        let v_lt = _mm256_set1_epi8(b'<' as i8);
        let v_amp = _mm256_set1_epi8(b'&' as i8);
        let v_del = _mm256_set1_epi8(0x7F);
        let v_space = _mm256_set1_epi8(0x20);

        while i + 32 <= len {
            let chunk = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
            // Signed `0x20 > chunk` matches `0x00..=0x1F` (0..=31) and `0x80..=0xFF` (-128..=-1)
            let is_ctrl_or_high = _mm256_cmpgt_epi8(v_space, chunk);
            let is_quote = _mm256_cmpeq_epi8(chunk, v_quote);
            let is_lt = _mm256_cmpeq_epi8(chunk, v_lt);
            let is_amp = _mm256_cmpeq_epi8(chunk, v_amp);
            let is_del = _mm256_cmpeq_epi8(chunk, v_del);

            let stop_vec = _mm256_or_si256(
                _mm256_or_si256(is_ctrl_or_high, is_quote),
                _mm256_or_si256(_mm256_or_si256(is_lt, is_amp), is_del),
            );
            let mask = _mm256_movemask_epi8(stop_vec) as u32;
            if mask != 0 {
                return i + mask.trailing_zeros() as usize;
            }
            i += 32;
        }
    }
    i + skip_xml_attr_bytes_swar(&bytes[i..], quote)
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
unsafe fn skip_xml_text_bytes_neon(bytes: &[u8]) -> usize {
    use std::arch::aarch64::*;
    let mut i = 0;
    let len = bytes.len();
    let ptr = bytes.as_ptr();

    // SAFETY: Caller guarantees `aarch64` with `neon` target feature enabled.
    // The loop condition `i + 16 <= len` ensures `ptr.add(i)` and the 16-byte `vld1q_u8`
    // load always read strictly within `bytes`.
    unsafe {
        let v_lt = vdupq_n_u8(b'<');
        let v_amp = vdupq_n_u8(b'&');
        let v_rb = vdupq_n_u8(b']');
        let v_tab = vdupq_n_u8(b'\t');
        let v_lf = vdupq_n_u8(b'\n');
        let v_space = vdupq_n_u8(0x20);
        let v_high = vdupq_n_u8(0x7F);

        while i + 16 <= len {
            let chunk = vld1q_u8(ptr.add(i));
            let is_ctrl = vcltq_u8(chunk, v_space);
            let is_high = vcgeq_u8(chunk, v_high);
            let is_tab = vceqq_u8(chunk, v_tab);
            let is_lf = vceqq_u8(chunk, v_lf);
            let allowed_ws = vorrq_u8(is_tab, is_lf);
            let bad_ctrl = vbicq_u8(is_ctrl, allowed_ws);

            let is_lt = vceqq_u8(chunk, v_lt);
            let is_amp = vceqq_u8(chunk, v_amp);
            let is_rb = vceqq_u8(chunk, v_rb);

            let stop = vorrq_u8(
                vorrq_u8(bad_ctrl, is_high),
                vorrq_u8(vorrq_u8(is_lt, is_amp), is_rb),
            );
            if vmaxvq_u8(stop) != 0 {
                for j in 0..16 {
                    if !is_fast_text_byte(bytes[i + j]) {
                        return i + j;
                    }
                }
            }
            i += 16;
        }
    }
    i + skip_xml_text_bytes_swar(&bytes[i..])
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
unsafe fn skip_xml_attr_bytes_neon(bytes: &[u8], quote: u8) -> usize {
    use std::arch::aarch64::*;
    let mut i = 0;
    let len = bytes.len();
    let ptr = bytes.as_ptr();

    // SAFETY: Caller guarantees `aarch64` with `neon` target feature enabled.
    // The loop condition `i + 16 <= len` ensures `ptr.add(i)` and the 16-byte `vld1q_u8`
    // load always read strictly within `bytes`.
    unsafe {
        let v_quote = vdupq_n_u8(quote);
        let v_lt = vdupq_n_u8(b'<');
        let v_amp = vdupq_n_u8(b'&');
        let v_space = vdupq_n_u8(0x20);
        let v_high = vdupq_n_u8(0x7F);

        while i + 16 <= len {
            let chunk = vld1q_u8(ptr.add(i));
            let is_ctrl = vcltq_u8(chunk, v_space);
            let is_high = vcgeq_u8(chunk, v_high);
            let is_quote = vceqq_u8(chunk, v_quote);
            let is_lt = vceqq_u8(chunk, v_lt);
            let is_amp = vceqq_u8(chunk, v_amp);

            let stop = vorrq_u8(
                vorrq_u8(is_ctrl, is_high),
                vorrq_u8(vorrq_u8(is_quote, is_lt), is_amp),
            );
            if vmaxvq_u8(stop) != 0 {
                for j in 0..16 {
                    if !is_fast_attr_byte(bytes[i + j], quote) {
                        return i + j;
                    }
                }
            }
            i += 16;
        }
    }
    i + skip_xml_attr_bytes_swar(&bytes[i..], quote)
}

/// Validates whether a Unicode scalar value matches the hardened XML 1.0 `Char` production
/// (Ruling 2, CWE-20 & CWE-150: rejects `0x7F` DEL and `0x80..=0x9F` C1 control characters):
/// `Char ::= #x9 | #xA | #xD | [#x20-#x7E] | [#xA0-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`
#[inline]
pub const fn is_xml_char(cp: u32) -> bool {
    cp == 0x09
        || cp == 0x0A
        || cp == 0x0D
        || (cp >= 0x20 && cp <= 0x7E)
        || (cp >= 0xA0 && cp <= 0xD7FF)
        || (cp >= 0xE000 && cp <= 0xFFFD)
        || (cp >= 0x10000 && cp <= 0x10FFFF)
}

/// Validates whether a Unicode scalar value matches W3C XML 1.0 `NameStartChar`.
#[inline]
pub const fn is_name_start_char(cp: u32) -> bool {
    cp == b':' as u32
        || (cp >= b'A' as u32 && cp <= b'Z' as u32)
        || cp == b'_' as u32
        || (cp >= b'a' as u32 && cp <= b'z' as u32)
        || (cp >= 0xC0 && cp <= 0xD6)
        || (cp >= 0xD8 && cp <= 0xF6)
        || (cp >= 0xF8 && cp <= 0x2FF)
        || (cp >= 0x370 && cp <= 0x37D)
        || (cp >= 0x37F && cp <= 0x1FFF)
        || (cp >= 0x200C && cp <= 0x200D)
        || (cp >= 0x2070 && cp <= 0x218F)
        || (cp >= 0x2C00 && cp <= 0x2FEF)
        || (cp >= 0x3001 && cp <= 0xD7FF)
        || (cp >= 0xF900 && cp <= 0xFDCF)
        || (cp >= 0xFDF0 && cp <= 0xFFFD)
        || (cp >= 0x10000 && cp <= 0xEFFFF)
}

/// Validates whether a Unicode scalar value matches W3C XML 1.0 `NameChar`.
#[inline]
pub const fn is_name_char(cp: u32) -> bool {
    is_name_start_char(cp)
        || cp == b'-' as u32
        || cp == b'.' as u32
        || (cp >= b'0' as u32 && cp <= b'9' as u32)
        || cp == 0xB7
        || (cp >= 0x0300 && cp <= 0x036F)
        || (cp >= 0x203F && cp <= 0x2040)
}

#[inline]
const fn is_xml_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

/// Decodes one UTF-8 scalar from `bytes[pos..]`, returning `(codepoint, byte_len)`.
#[inline]
fn decode_utf8_at(bytes: &[u8], pos: usize) -> Result<(u32, usize), ()> {
    let b0 = bytes[pos];
    if b0 < 0x80 {
        return Ok((b0 as u32, 1));
    }
    let rem = bytes.len() - pos;
    if (b0 & 0xE0) == 0xC0 {
        if rem < 2 {
            return Err(());
        }
        let b1 = bytes[pos + 1];
        if (b1 & 0xC0) != 0x80 {
            return Err(());
        }
        let cp = (((b0 & 0x1F) as u32) << 6) | ((b1 & 0x3F) as u32);
        if cp < 0x80 {
            return Err(());
        }
        Ok((cp, 2))
    } else if (b0 & 0xF0) == 0xE0 {
        if rem < 3 {
            return Err(());
        }
        let b1 = bytes[pos + 1];
        let b2 = bytes[pos + 2];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 {
            return Err(());
        }
        let cp = (((b0 & 0x0F) as u32) << 12) | (((b1 & 0x3F) as u32) << 6) | ((b2 & 0x3F) as u32);
        if cp < 0x800 || (0xD800..=0xDFFF).contains(&cp) {
            return Err(());
        }
        Ok((cp, 3))
    } else if (b0 & 0xF8) == 0xF0 {
        if rem < 4 {
            return Err(());
        }
        let b1 = bytes[pos + 1];
        let b2 = bytes[pos + 2];
        let b3 = bytes[pos + 3];
        if (b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
            return Err(());
        }
        let cp = (((b0 & 0x07) as u32) << 18)
            | (((b1 & 0x3F) as u32) << 12)
            | (((b2 & 0x3F) as u32) << 6)
            | ((b3 & 0x3F) as u32);
        if !(0x10000..=0x10FFFF).contains(&cp) {
            return Err(());
        }
        Ok((cp, 4))
    } else {
        Err(())
    }
}

/// Validates and splits a QName (`prefix:local` or `local`) according to W3C Namespaces in XML 1.0.
fn split_and_validate_qname(raw: &[u8]) -> Result<(Option<&[u8]>, &[u8]), XmlErrorKind> {
    if raw.is_empty() {
        return Err(XmlErrorKind::InvalidName);
    }
    let mut colon_pos = None;
    let mut i = 0;
    let mut is_start = true;
    while i < raw.len() {
        let b = raw[i];
        if b == b':' {
            if colon_pos.is_some() || i == 0 || i + 1 == raw.len() {
                return Err(XmlErrorKind::InvalidQName);
            }
            colon_pos = Some(i);
            is_start = true;
            i += 1;
            continue;
        }
        let (cp, len) = decode_utf8_at(raw, i).map_err(|()| XmlErrorKind::InvalidUtf8)?;
        if is_start {
            if !is_name_start_char(cp) || cp == b':' as u32 {
                return Err(XmlErrorKind::InvalidName);
            }
            is_start = false;
        } else if !is_name_char(cp) || cp == b':' as u32 {
            return Err(XmlErrorKind::InvalidName);
        }
        i += len;
    }
    if let Some(c) = colon_pos {
        Ok((Some(&raw[..c]), &raw[c + 1..]))
    } else {
        Ok((None, raw))
    }
}

/// Scans an XML `Name` starting at `input[pos..]`, returning its end offset.
fn scan_name(input: &[u8], pos: usize) -> Result<usize, (XmlErrorKind, usize)> {
    if pos >= input.len() {
        return Err((XmlErrorKind::UnexpectedEof, pos));
    }
    let (first_cp, first_len) =
        decode_utf8_at(input, pos).map_err(|()| (XmlErrorKind::InvalidUtf8, pos))?;
    if !is_name_start_char(first_cp) {
        return Err((XmlErrorKind::InvalidName, pos));
    }
    let mut i = pos + first_len;
    while i < input.len() {
        let b = input[i];
        if b < 0x80 {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':' {
                i += 1;
                continue;
            }
            break;
        }
        let (cp, len) = decode_utf8_at(input, i).map_err(|()| (XmlErrorKind::InvalidUtf8, i))?;
        if is_name_char(cp) {
            i += len;
        } else {
            break;
        }
    }
    Ok(i)
}

/// Validates and resolves an entity/character reference starting at `input[amp_pos]` (`&...;`).
/// Appends the resolved UTF-8 bytes to `resolved_out` if `Some`.
/// Returns the byte offset immediately after `;`.
fn validate_reference(
    input: &[u8],
    amp_pos: usize,
    mut resolved_out: Option<&mut Vec<u8>>,
) -> Result<usize, (XmlErrorKind, String, usize)> {
    let start = amp_pos + 1;
    if start >= input.len() {
        return Err((
            XmlErrorKind::UnexpectedEof,
            "unterminated entity or character reference at EOF".to_string(),
            amp_pos,
        ));
    }
    let mut semi = start;
    while semi < input.len() && input[semi] != b';' {
        if is_xml_space(input[semi])
            || input[semi] == b'<'
            || input[semi] == b'&'
            || (semi - start) > 64
        {
            return Err((
                XmlErrorKind::InvalidEntityRef,
                "malformed reference: missing closing ';'".to_string(),
                amp_pos,
            ));
        }
        semi += 1;
    }
    if semi >= input.len() {
        return Err((
            XmlErrorKind::UnexpectedEof,
            "unterminated reference: missing ';'".to_string(),
            amp_pos,
        ));
    }
    let body = &input[start..semi];
    if body.is_empty() {
        return Err((
            XmlErrorKind::InvalidEntityRef,
            "empty entity reference '&;'".to_string(),
            amp_pos,
        ));
    }
    if body[0] == b'#' {
        let num_spec = &body[1..];
        if num_spec.is_empty() {
            return Err((
                XmlErrorKind::InvalidCharRef,
                "empty numeric character reference '&#;'".to_string(),
                amp_pos,
            ));
        }
        let cp: u32 = if num_spec[0] == b'x' {
            let hex = &num_spec[1..];
            if hex.is_empty() {
                return Err((
                    XmlErrorKind::InvalidCharRef,
                    "empty hexadecimal character reference '&#x;'".to_string(),
                    amp_pos,
                ));
            }
            let mut val = 0u32;
            for &b in hex {
                let digit = match b {
                    b'0'..=b'9' => (b - b'0') as u32,
                    b'a'..=b'f' => (b - b'a' + 10) as u32,
                    b'A'..=b'F' => (b - b'A' + 10) as u32,
                    _ => {
                        return Err((
                            XmlErrorKind::InvalidCharRef,
                            "invalid hexadecimal digit in character reference".to_string(),
                            amp_pos,
                        ))
                    }
                };
                val = val
                    .checked_mul(16)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or_else(|| {
                        (
                            XmlErrorKind::InvalidCharRef,
                            "character reference out of Unicode range".to_string(),
                            amp_pos,
                        )
                    })?;
            }
            val
        } else if num_spec[0] == b'X' {
            return Err((
                XmlErrorKind::InvalidCharRef,
                "uppercase '&#X' is invalid in XML 1.0; use lowercase '&#x'".to_string(),
                amp_pos,
            ));
        } else {
            let mut val = 0u32;
            for &b in num_spec {
                if !b.is_ascii_digit() {
                    return Err((
                        XmlErrorKind::InvalidCharRef,
                        "invalid decimal digit in character reference".to_string(),
                        amp_pos,
                    ));
                }
                let digit = (b - b'0') as u32;
                val = val
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or_else(|| {
                        (
                            XmlErrorKind::InvalidCharRef,
                            "character reference out of Unicode range".to_string(),
                            amp_pos,
                        )
                    })?;
            }
            val
        };

        if !is_xml_char(cp) {
            return Err((
                XmlErrorKind::InvalidCharRef,
                format!(
                    "numeric character reference '&#x{:X};' is not a valid XML 1.0 Char",
                    cp
                ),
                amp_pos,
            ));
        }
        if let Some(ref mut out) = resolved_out {
            if let Some(ch) = char::from_u32(cp) {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
        Ok(semi + 1)
    } else {
        // Validate entity Name syntax
        let end_name = scan_name(body, 0)
            .map_err(|(k, _)| (k, "invalid entity reference name".to_string(), amp_pos))?;
        if end_name != body.len() || body.contains(&b':') {
            return Err((
                XmlErrorKind::InvalidEntityRef,
                "entity reference name must be a valid NCName".to_string(),
                amp_pos,
            ));
        }
        let replacement: u8 = match body {
            b"lt" => b'<',
            b"gt" => b'>',
            b"amp" => b'&',
            b"apos" => b'\'',
            b"quot" => b'"',
            _ => {
                let name_str = String::from_utf8_lossy(body);
                return Err((
                    XmlErrorKind::CustomEntityDisallowed,
                    format!(
                        "custom or undeclared entity reference '&{};' is not expanded",
                        name_str
                    ),
                    amp_pos,
                ));
            }
        };
        if let Some(ref mut out) = resolved_out {
            out.push(replacement);
        }
        Ok(semi + 1)
    }
}

/// Validates and scans an attribute value starting right after the opening quote (`quote_pos + 1`).
fn scan_attribute_value(
    input: &[u8],
    val_start: usize,
    quote: u8,
) -> Result<(usize, &[u8]), (XmlErrorKind, String, usize)> {
    let mut i = val_start;
    let len = input.len();
    while i < len {
        let fast = skip_xml_attr_bytes(&input[i..], quote);
        i += fast;
        if i >= len {
            break;
        }
        let b = input[i];
        if b == quote {
            return Ok((i + 1, &input[val_start..i]));
        } else if b == b'<' {
            return Err((
                XmlErrorKind::UnescapedLtInAttribute,
                "unescaped '<' is not permitted inside an attribute value".to_string(),
                i,
            ));
        } else if b == b'&' {
            i = validate_reference(input, i, None)?;
        } else if b < 0x20 {
            if b == b'\t' || b == b'\n' || b == b'\r' {
                i += 1;
            } else {
                return Err((
                    XmlErrorKind::InvalidChar,
                    format!("illegal control character 0x{:02X} in attribute value", b),
                    i,
                ));
            }
        } else {
            let (cp, char_len) = decode_utf8_at(input, i).map_err(|()| {
                (
                    XmlErrorKind::InvalidUtf8,
                    "invalid UTF-8 byte sequence in attribute value".to_string(),
                    i,
                )
            })?;
            if !is_xml_char(cp) {
                return Err((
                    XmlErrorKind::InvalidChar,
                    format!("character U+{:04X} is not a valid XML 1.0 Char", cp),
                    i,
                ));
            }
            i += char_len;
        }
    }
    Err((
        XmlErrorKind::UnexpectedEof,
        "unterminated attribute value at EOF".to_string(),
        val_start.saturating_sub(1),
    ))
}

/// Normalizes an attribute value when used as a Namespace URI (`xmlns` / `xmlns:prefix`) or `xml:space`.
fn resolve_attr_value<'a>(raw: &'a [u8]) -> Cow<'a, [u8]> {
    if !raw
        .iter()
        .any(|&b| b == b'&' || b == b'\r' || b == b'\n' || b == b'\t')
    {
        return Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b == b'&' {
            if let Ok(next) = validate_reference(raw, i, Some(&mut out)) {
                i = next;
                continue;
            }
        } else if b == b'\r' {
            if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                i += 1;
            }
            out.push(b' ');
            i += 1;
            continue;
        } else if b == b'\n' || b == b'\t' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    Cow::Owned(out)
}

#[inline]
fn starts_with_keyword_ci(bytes: &[u8], kw: &[u8]) -> bool {
    if bytes.len() < kw.len() || !bytes[..kw.len()].eq_ignore_ascii_case(kw) {
        return false;
    }
    if bytes.len() == kw.len() {
        return true;
    }
    let next = bytes[kw.len()];
    is_xml_space(next) || matches!(next, b'"' | b'\'' | b'>' | b'[')
}

/// Single-pass streaming XML 1.0 (Fifth Edition) + Namespaces in XML 1.0 engine.
pub struct StreamingEngine<'a> {
    input: &'a [u8],
    config: &'a Config,
    pos: usize,
    stack: Vec<XmlFrame<'a>>,
    diagnostics: Vec<XmlError>,
    raw_attr_set: RawKeySet<'a>,
    expanded_attr_set: KeySet<(Cow<'a, [u8]>, &'a [u8])>,
    out: Option<Vec<u8>>,
    seen_root: bool,
    root_closed: bool,
    seen_doctype: bool,
}

impl<'a> StreamingEngine<'a> {
    pub fn new(input: &'a [u8], config: &'a Config, build_output: bool) -> Self {
        let max_out = config.max_output_bytes.min(DEFAULT_MAX_OUTPUT_BYTES);
        let out = if build_output {
            let init_cap = input.len().min(max_out).min(64 * 1024);
            Some(Vec::with_capacity(init_cap))
        } else {
            None
        };
        Self {
            input,
            config,
            pos: 0,
            stack: Vec::with_capacity(32),
            diagnostics: Vec::new(),
            raw_attr_set: RawKeySet::new(),
            expanded_attr_set: KeySet::new(),
            out,
            seen_root: false,
            root_closed: false,
            seen_doctype: false,
        }
    }

    fn emit_error(&mut self, kind: XmlErrorKind, msg: impl Into<String>, offset: usize) {
        if self.diagnostics.len() < self.config.max_diagnostics.min(MAX_LINT_DIAGNOSTICS) {
            let (line, col) = line_col_at(self.input, offset);
            self.diagnostics
                .push(XmlError::new(kind, msg, offset, line, col));
        }
    }

    fn emit_span_error(
        &mut self,
        kind: XmlErrorKind,
        msg: impl Into<String>,
        start_offset: usize,
        end_offset: usize,
    ) {
        if self.diagnostics.len() < self.config.max_diagnostics.min(MAX_LINT_DIAGNOSTICS) {
            let (line, col) = line_col_at(self.input, start_offset);
            self.diagnostics.push(XmlError::with_span(
                kind,
                msg,
                start_offset,
                end_offset,
                line,
                col,
            ));
        }
    }

    fn write_bytes(&mut self, bytes: &[u8], offset: usize) -> bool {
        if let Some(ref mut out) = self.out {
            let max_out = self.config.max_output_bytes.min(DEFAULT_MAX_OUTPUT_BYTES);
            let mut sink = BoundedVecRefSink::new(out, max_out);
            if !sink.write_slice(bytes) {
                self.emit_error(
                    XmlErrorKind::OutputTooLarge,
                    format!(
                        "formatted output exceeds maximum limit of {} bytes",
                        max_out
                    ),
                    offset,
                );
                return false;
            }
        }
        true
    }

    fn write_indent(&mut self, depth: usize, offset: usize) -> bool {
        if self.out.is_none() || depth == 0 {
            return true;
        }
        if self.config.use_tabs {
            for _ in 0..depth {
                if !self.write_bytes(b"\t", offset) {
                    return false;
                }
            }
        } else {
            let total = depth.saturating_mul(self.config.indent_width);
            const SPACES: &[u8; 64] = &[b' '; 64];
            let mut rem = total;
            while rem > 0 {
                let chunk = rem.min(SPACES.len());
                if !self.write_bytes(&SPACES[..chunk], offset) {
                    return false;
                }
                rem -= chunk;
            }
        }
        true
    }

    /// Runs the single-pass streaming validation (and optional formatting).
    pub fn run(mut self) -> (Vec<XmlError>, Option<Vec<u8>>) {
        let max_in = self.config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
        if self.input.len() > max_in {
            self.emit_error(
                XmlErrorKind::InputTooLarge,
                format!(
                    "input size ({} bytes) exceeds maximum limit of {} bytes",
                    self.input.len(),
                    max_in
                ),
                0,
            );
            return (self.diagnostics, None);
        }

        // Step 1: Encoding & BOM Gate at Offset 0
        if !self.check_bom_and_encoding_gate() {
            return (self.diagnostics, None);
        }

        // Step 2: Optional XML Declaration at byte 0 (or byte 3 right after UTF-8 BOM)
        let decl_allowed_pos = self.pos;
        if self.input[self.pos..].starts_with(b"<?")
            && !self.try_parse_initial_xml_decl(decl_allowed_pos)
        {
            return (self.diagnostics, None);
        }

        // Step 3: Main single-pass state machine
        while self.pos < self.input.len() {
            if self.diagnostics.len() >= self.config.max_diagnostics.min(MAX_LINT_DIAGNOSTICS) {
                break;
            }
            if self.input[self.pos] == b'<' {
                if !self.parse_markup() {
                    break;
                }
            } else if !self.parse_text_content() {
                break;
            }
        }

        // Step 4: Final well-formedness checks at EOF
        if self.diagnostics.is_empty() {
            if let Some(unclosed) = self.stack.pop() {
                let name = String::from_utf8_lossy(unclosed.raw_name);
                self.diagnostics.push(XmlError::new(
                    XmlErrorKind::UnclosedElement,
                    format!("unclosed element '<{}>' at end of document", name),
                    unclosed.open_offset,
                    unclosed.open_line,
                    unclosed.open_col,
                ));
            } else if !self.seen_root {
                self.emit_error(
                    XmlErrorKind::MissingRootElement,
                    "XML document must contain a root element",
                    self.pos,
                );
            }
        }

        if let Some(ref mut out) = self.out {
            if !out.is_empty() && !out.ends_with(b"\n") {
                let _ = self.write_bytes(b"\n", self.pos);
            }
        }

        let output = if self.diagnostics.is_empty() {
            self.out
        } else {
            None
        };
        (self.diagnostics, output)
    }

    fn check_bom_and_encoding_gate(&mut self) -> bool {
        let b = self.input;
        if b.len() >= 4
            && ((b[0] == 0x00 && b[1] == 0x00 && b[2] == 0xFE && b[3] == 0xFF)
                || (b[0] == 0xFF && b[1] == 0xFE && b[2] == 0x00 && b[3] == 0x00))
        {
            self.emit_span_error(
                XmlErrorKind::UnsupportedEncoding,
                "UTF-32 BOM detected at offset 0; only UTF-8 encoding is supported",
                0,
                4,
            );
            return false;
        }
        if b.len() >= 2 {
            if b[0] == 0xFF && b[1] == 0xFE {
                self.emit_span_error(
                    XmlErrorKind::UnsupportedEncoding,
                    "UTF-16LE BOM (0xFF 0xFE) detected at offset 0; only UTF-8 encoding is supported",
                    0,
                    2,
                );
                return false;
            }
            if b[0] == 0xFE && b[1] == 0xFF {
                self.emit_span_error(
                    XmlErrorKind::UnsupportedEncoding,
                    "UTF-16BE BOM (0xFE 0xFF) detected at offset 0; only UTF-8 encoding is supported",
                    0,
                    2,
                );
                return false;
            }
        }
        if b.len() >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
            self.pos = 3;
        }
        true
    }

    fn try_parse_initial_xml_decl(&mut self, start_pos: usize) -> bool {
        let name_end = match scan_name(self.input, start_pos + 2) {
            Ok(end) => end,
            Err((k, off)) => {
                self.emit_error(k, "invalid target name after '<?'", off);
                return false;
            }
        };
        let target = &self.input[start_pos + 2..name_end];
        if target.eq_ignore_ascii_case(b"xml") {
            if target != b"xml" {
                self.emit_span_error(
                    XmlErrorKind::ReservedPiTarget,
                    "processing instruction target matching 'xml' case-insensitively is reserved; XML declaration must be lowercase '<?xml'",
                    start_pos,
                    name_end,
                );
                return false;
            }
            if name_end >= self.input.len() || !is_xml_space(self.input[name_end]) {
                self.emit_error(
                    XmlErrorKind::MalformedXmlDecl,
                    "XML declaration '<?xml' must be followed by whitespace and version=\"1.0\"",
                    name_end,
                );
                return false;
            }
            return self.parse_xml_decl_body(start_pos, name_end);
        }
        true
    }

    fn parse_xml_decl_body(&mut self, decl_start: usize, mut i: usize) -> bool {
        let len = self.input.len();
        let mut step = 0u8; // 0: need version, 1: allow encoding or standalone, 2: allow standalone, 3: done

        while i < len {
            let ws_start = i;
            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            let saw_space = i > ws_start;

            if i + 1 < len && self.input[i] == b'?' && self.input[i + 1] == b'>' {
                if step == 0 {
                    self.emit_span_error(
                        XmlErrorKind::MalformedXmlDecl,
                        "XML declaration is missing required version=\"1.0\" attribute",
                        decl_start,
                        i + 2,
                    );
                    return false;
                }
                self.pos = i + 2;
                if !self.write_bytes(&self.input[decl_start..self.pos], decl_start) {
                    return false;
                }
                if !self.write_bytes(b"\n", self.pos) {
                    return false;
                }
                return true;
            }

            if !saw_space {
                self.emit_error(
                    XmlErrorKind::MalformedXmlDecl,
                    "whitespace is required between pseudo-attributes in XML declaration",
                    i,
                );
                return false;
            }

            let attr_start = i;
            while i < len && self.input[i].is_ascii_alphabetic() {
                i += 1;
            }
            let attr_name = &self.input[attr_start..i];
            if attr_name.is_empty() {
                self.emit_error(
                    XmlErrorKind::MalformedXmlDecl,
                    "unexpected character in XML declaration",
                    i,
                );
                return false;
            }

            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            if i >= len || self.input[i] != b'=' {
                self.emit_error(
                    XmlErrorKind::MalformedXmlDecl,
                    "expected '=' after pseudo-attribute name in XML declaration",
                    i,
                );
                return false;
            }
            i += 1;
            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            if i >= len || (self.input[i] != b'"' && self.input[i] != b'\'') {
                self.emit_error(
                    XmlErrorKind::MalformedXmlDecl,
                    "expected quoted value in XML declaration",
                    i,
                );
                return false;
            }
            let quote = self.input[i];
            i += 1;
            let val_start = i;
            while i < len && self.input[i] != quote {
                let (cp, char_len) = match decode_utf8_at(self.input, i) {
                    Ok(v) => v,
                    Err(()) => {
                        self.emit_error(
                            XmlErrorKind::InvalidUtf8,
                            "invalid UTF-8 inside XML declaration attribute value",
                            i,
                        );
                        return false;
                    }
                };
                if !is_xml_char(cp) {
                    self.emit_error(
                        XmlErrorKind::InvalidChar,
                        format!(
                            "illegal XML character U+{:04X} inside XML declaration attribute value",
                            cp
                        ),
                        i,
                    );
                    return false;
                }
                i += char_len;
            }
            if i >= len {
                self.emit_error(
                    XmlErrorKind::UnexpectedEof,
                    "unterminated quoted value in XML declaration",
                    val_start,
                );
                return false;
            }
            let val = &self.input[val_start..i];
            i += 1; // consume closing quote

            match attr_name {
                b"version" => {
                    if step != 0 {
                        self.emit_span_error(
                            XmlErrorKind::MalformedXmlDecl,
                            "'version' must be the first attribute in XML declaration and cannot be duplicated",
                            attr_start,
                            i,
                        );
                        return false;
                    }
                    if val != b"1.0" {
                        self.emit_span_error(
                            XmlErrorKind::MalformedXmlDecl,
                            format!(
                                "unsupported XML version '{}'; only version=\"1.0\" is supported",
                                String::from_utf8_lossy(val)
                            ),
                            val_start,
                            i - 1,
                        );
                        return false;
                    }
                    step = 1;
                }
                b"encoding" => {
                    if step != 1 {
                        self.emit_span_error(
                            XmlErrorKind::MalformedXmlDecl,
                            "'encoding' must appear after 'version' and before 'standalone' in XML declaration",
                            attr_start,
                            i,
                        );
                        return false;
                    }
                    if !val.eq_ignore_ascii_case(b"UTF-8") {
                        self.emit_span_error(
                            XmlErrorKind::UnsupportedEncoding,
                            format!(
                                "unsupported encoding '{}'; only UTF-8 is supported",
                                String::from_utf8_lossy(val)
                            ),
                            val_start,
                            i - 1,
                        );
                        return false;
                    }
                    step = 2;
                }
                b"standalone" => {
                    if step == 0 || step >= 3 {
                        self.emit_span_error(
                            XmlErrorKind::MalformedXmlDecl,
                            "'standalone' must appear last in XML declaration",
                            attr_start,
                            i,
                        );
                        return false;
                    }
                    if val != b"yes" && val != b"no" {
                        self.emit_span_error(
                            XmlErrorKind::MalformedXmlDecl,
                            "standalone attribute in XML declaration must be \"yes\" or \"no\"",
                            val_start,
                            i - 1,
                        );
                        return false;
                    }
                    step = 3;
                }
                _ => {
                    self.emit_span_error(
                        XmlErrorKind::MalformedXmlDecl,
                        format!(
                            "unknown attribute '{}' in XML declaration",
                            String::from_utf8_lossy(attr_name)
                        ),
                        attr_start,
                        i,
                    );
                    return false;
                }
            }
        }

        self.emit_error(
            XmlErrorKind::UnexpectedEof,
            "unterminated XML declaration: expected '?>'",
            decl_start,
        );
        false
    }

    fn parse_markup(&mut self) -> bool {
        let start = self.pos;
        let rem = &self.input[start..];
        if rem.len() < 2 {
            self.emit_error(XmlErrorKind::UnexpectedEof, "unexpected '<' at EOF", start);
            return false;
        }
        match rem[1] {
            b'?' => self.parse_pi(),
            b'!' => {
                if rem.starts_with(b"<!--") {
                    self.parse_comment()
                } else if rem.starts_with(b"<![CDATA[") {
                    self.parse_cdata()
                } else if rem.starts_with(b"<!DOCTYPE") {
                    self.parse_doctype()
                } else {
                    self.emit_error(
                        XmlErrorKind::UnexpectedChar,
                        "unrecognized markup declaration after '<!'",
                        start,
                    );
                    false
                }
            }
            b'/' => self.parse_end_tag(),
            _ => self.parse_start_or_empty_tag(),
        }
    }

    fn parse_pi(&mut self) -> bool {
        let start = self.pos;
        let name_end = match scan_name(self.input, start + 2) {
            Ok(end) => end,
            Err((k, off)) => {
                self.emit_error(k, "invalid processing instruction target name", off);
                return false;
            }
        };
        let target = &self.input[start + 2..name_end];
        if target.eq_ignore_ascii_case(b"xml") {
            if target == b"xml" {
                self.emit_span_error(
                    XmlErrorKind::MisplacedXmlDecl,
                    "XML declaration '<?xml ...?>' is only allowed at the very beginning of the document (byte 0, or byte 3 after UTF-8 BOM)",
                    start,
                    name_end,
                );
            } else {
                self.emit_span_error(
                    XmlErrorKind::ReservedPiTarget,
                    format!(
                        "processing instruction target '{}' is reserved (matches 'xml' case-insensitively)",
                        String::from_utf8_lossy(target)
                    ),
                    start,
                    name_end,
                );
            }
            return false;
        }
        if target.contains(&b':') {
            self.emit_span_error(
                XmlErrorKind::InvalidPi,
                "processing instruction target must not contain ':' in Namespaces in XML 1.0",
                start + 2,
                name_end,
            );
            return false;
        }

        let mut i = name_end;
        let len = self.input.len();
        if i + 1 < len && self.input[i] == b'?' && self.input[i + 1] == b'>' {
            i += 2;
        } else {
            if i >= len || !is_xml_space(self.input[i]) {
                self.emit_error(
                    XmlErrorKind::InvalidPi,
                    "processing instruction target must be followed by whitespace or '?>'",
                    i,
                );
                return false;
            }
            let mut found_end = false;
            while i < len {
                if i + 1 < len && self.input[i] == b'?' && self.input[i + 1] == b'>' {
                    i += 2;
                    found_end = true;
                    break;
                }
                let (cp, char_len) = match decode_utf8_at(self.input, i) {
                    Ok(v) => v,
                    Err(()) => {
                        self.emit_error(
                            XmlErrorKind::InvalidUtf8,
                            "invalid UTF-8 inside processing instruction",
                            i,
                        );
                        return false;
                    }
                };
                if !is_xml_char(cp) {
                    self.emit_error(
                        XmlErrorKind::InvalidChar,
                        format!(
                            "illegal XML character U+{:04X} in processing instruction",
                            cp
                        ),
                        i,
                    );
                    return false;
                }
                i += char_len;
            }
            if !found_end {
                self.emit_error(
                    XmlErrorKind::UnexpectedEof,
                    "unterminated processing instruction: expected '?>'",
                    start,
                );
                return false;
            }
        }

        self.pos = i;
        if self.out.is_some() {
            let preserve = self.current_preserve_whitespace();
            let depth = self.stack.len();
            if !preserve && depth > 0 && !self.write_indent(depth, start) {
                return false;
            }
            if !self.write_bytes(&self.input[start..self.pos], start) {
                return false;
            }
            if !preserve && !self.write_bytes(b"\n", start) {
                return false;
            }
        }
        true
    }

    fn parse_comment(&mut self) -> bool {
        let start = self.pos;
        let mut i = start + 4; // after <!--
        let len = self.input.len();
        while i < len {
            if self.input[i] == b'-' && i + 1 < len && self.input[i + 1] == b'-' {
                if i + 2 < len && self.input[i + 2] == b'>' {
                    self.pos = i + 3;
                    if self.out.is_some() {
                        let preserve = self.current_preserve_whitespace();
                        let depth = self.stack.len();
                        if !preserve && depth > 0 && !self.write_indent(depth, start) {
                            return false;
                        }
                        if !self.write_bytes(&self.input[start..self.pos], start) {
                            return false;
                        }
                        if !preserve && !self.write_bytes(b"\n", start) {
                            return false;
                        }
                    }
                    return true;
                }
                self.emit_span_error(
                    XmlErrorKind::InvalidComment,
                    "'--' is not permitted inside an XML comment",
                    i,
                    i + 2,
                );
                return false;
            }
            let (cp, char_len) = match decode_utf8_at(self.input, i) {
                Ok(v) => v,
                Err(()) => {
                    self.emit_error(XmlErrorKind::InvalidUtf8, "invalid UTF-8 inside comment", i);
                    return false;
                }
            };
            if !is_xml_char(cp) {
                self.emit_error(
                    XmlErrorKind::InvalidChar,
                    format!("illegal XML character U+{:04X} inside comment", cp),
                    i,
                );
                return false;
            }
            i += char_len;
        }
        self.emit_error(
            XmlErrorKind::UnexpectedEof,
            "unterminated XML comment: expected '-->'",
            start,
        );
        false
    }

    fn parse_cdata(&mut self) -> bool {
        let start = self.pos;
        if self.stack.is_empty() {
            self.emit_error(
                XmlErrorKind::ContentOutsideRoot,
                "CDATA section is not permitted outside the root element",
                start,
            );
            return false;
        }
        if let Some(top) = self.stack.last_mut() {
            top.has_non_ws_text = true;
        }
        let mut i = start + 9; // after <![CDATA[
        let len = self.input.len();
        while i < len {
            if self.input[i] == b']'
                && i + 2 < len
                && self.input[i + 1] == b']'
                && self.input[i + 2] == b'>'
            {
                self.pos = i + 3;
                return self.write_bytes(&self.input[start..self.pos], start);
            }
            let (cp, char_len) = match decode_utf8_at(self.input, i) {
                Ok(v) => v,
                Err(()) => {
                    self.emit_error(
                        XmlErrorKind::InvalidUtf8,
                        "invalid UTF-8 inside CDATA section",
                        i,
                    );
                    return false;
                }
            };
            if !is_xml_char(cp) {
                self.emit_error(
                    XmlErrorKind::InvalidChar,
                    format!("illegal XML character U+{:04X} inside CDATA section", cp),
                    i,
                );
                return false;
            }
            i += char_len;
        }
        self.emit_error(
            XmlErrorKind::UnexpectedEof,
            "unterminated CDATA section: expected ']]>'",
            start,
        );
        false
    }

    fn parse_doctype(&mut self) -> bool {
        let start = self.pos;
        if self.config.disallow_doctype {
            self.emit_span_error(
                XmlErrorKind::DisallowedDoctype,
                "<!DOCTYPE> declaration is disallowed in --strict / --disallow-doctype mode",
                start,
                start + 9,
            );
            return false;
        }
        if self.seen_root || !self.stack.is_empty() {
            self.emit_span_error(
                XmlErrorKind::MalformedDoctype,
                "<!DOCTYPE> declaration must appear in the prolog before the root element",
                start,
                start + 9,
            );
            return false;
        }
        if self.seen_doctype {
            self.emit_span_error(
                XmlErrorKind::MalformedDoctype,
                "multiple <!DOCTYPE> declarations are not permitted",
                start,
                start + 9,
            );
            return false;
        }
        self.seen_doctype = true;

        let mut i = start + 9; // after <!DOCTYPE
        let len = self.input.len();
        if i >= len || !is_xml_space(self.input[i]) {
            self.emit_error(
                XmlErrorKind::MalformedDoctype,
                "expected whitespace after '<!DOCTYPE'",
                i,
            );
            return false;
        }
        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if i < len && self.input[i] == b'%' {
            self.emit_error(
                XmlErrorKind::ExternalEntityDisallowed,
                "parameter entity references ('%') are disallowed in <!DOCTYPE>",
                i,
            );
            return false;
        }
        let name_end = match scan_name(self.input, i) {
            Ok(end) => end,
            Err((XmlErrorKind::InvalidUtf8, off)) => {
                self.emit_error(
                    XmlErrorKind::InvalidUtf8,
                    "invalid UTF-8 in <!DOCTYPE> name",
                    off,
                );
                return false;
            }
            Err((XmlErrorKind::UnexpectedEof, off)) => {
                self.emit_error(
                    XmlErrorKind::UnexpectedEof,
                    "unterminated <!DOCTYPE> declaration at EOF",
                    off,
                );
                return false;
            }
            Err((_, off)) => {
                self.emit_error(
                    XmlErrorKind::MalformedDoctype,
                    "expected valid root name in <!DOCTYPE>",
                    off,
                );
                return false;
            }
        };
        let doctype_name = &self.input[i..name_end];
        if split_and_validate_qname(doctype_name).is_err() {
            self.emit_span_error(
                XmlErrorKind::InvalidQName,
                "invalid QName in <!DOCTYPE> declaration",
                i,
                name_end,
            );
            return false;
        }
        i = name_end;

        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if i >= len {
            self.emit_error(
                XmlErrorKind::UnexpectedEof,
                "unterminated <!DOCTYPE> declaration at EOF",
                start,
            );
            return false;
        }

        // Ruling 1: Check tokens before '[' or '>' at the root <!DOCTYPE> level
        if self.input[i] != b'[' && self.input[i] != b'>' {
            if self.input[i] == b'%' {
                self.emit_error(
                    XmlErrorKind::ExternalEntityDisallowed,
                    "parameter entity references ('%') are disallowed in <!DOCTYPE>",
                    i,
                );
                return false;
            }
            if starts_with_keyword_ci(&self.input[i..], b"SYSTEM")
                || starts_with_keyword_ci(&self.input[i..], b"PUBLIC")
            {
                self.emit_span_error(
                    XmlErrorKind::ExternalEntityDisallowed,
                    "external SYSTEM/PUBLIC DTD subsets are disallowed (Ruling 1, CWE-611)",
                    i,
                    (i + 6).min(len),
                );
                return false;
            }
            self.emit_error(
                XmlErrorKind::MalformedDoctype,
                "unexpected token in <!DOCTYPE>; expected '[' or '>'",
                i,
            );
            return false;
        }

        if self.input[i] == b'>' {
            self.pos = i + 1;
            if !self.write_bytes(&self.input[start..self.pos], start) {
                return false;
            }
            return self.write_bytes(b"\n", self.pos);
        }

        // Now self.input[i] == b'[': enter internal DTD subset
        i += 1;
        let mut markup_depth = 0usize;
        let mut in_notation_decl = false;

        while i < len {
            let b = self.input[i];
            if b == b'"' || b == b'\'' {
                let quote = b;
                let q_start = i;
                i += 1;
                while i < len && self.input[i] != quote {
                    let (cp, char_len) = match decode_utf8_at(self.input, i) {
                        Ok(v) => v,
                        Err(()) => {
                            self.emit_error(
                                XmlErrorKind::InvalidUtf8,
                                "invalid UTF-8 in DOCTYPE literal",
                                i,
                            );
                            return false;
                        }
                    };
                    if !is_xml_char(cp) {
                        self.emit_error(
                            XmlErrorKind::InvalidChar,
                            "illegal character in DOCTYPE literal",
                            i,
                        );
                        return false;
                    }
                    i += char_len;
                }
                if i >= len {
                    self.emit_error(
                        XmlErrorKind::UnexpectedEof,
                        "unterminated quoted literal in <!DOCTYPE>",
                        q_start,
                    );
                    return false;
                }
                i += 1;
            } else if b == b']' && markup_depth == 0 {
                i += 1;
                while i < len && is_xml_space(self.input[i]) {
                    i += 1;
                }
                if i < len && self.input[i] == b'%' {
                    self.emit_error(
                        XmlErrorKind::ExternalEntityDisallowed,
                        "parameter entity references ('%') are disallowed in <!DOCTYPE>",
                        i,
                    );
                    return false;
                }
                if i >= len || self.input[i] != b'>' {
                    self.emit_error(
                        XmlErrorKind::MalformedDoctype,
                        "expected '>' after internal DTD subset ']'",
                        i,
                    );
                    return false;
                }
                self.pos = i + 1;
                if !self.write_bytes(&self.input[start..self.pos], start) {
                    return false;
                }
                return self.write_bytes(b"\n", self.pos);
            } else if b == b'<' {
                if markup_depth > 0 {
                    self.emit_error(
                        XmlErrorKind::MalformedDoctype,
                        "nested markup declarations are not allowed inside DTD subset",
                        i,
                    );
                    return false;
                }
                if self.input[i..].starts_with(b"<!--") {
                    let saved = self.pos;
                    let saved_out = self.out.take();
                    self.pos = i;
                    let ok = self.parse_comment();
                    self.out = saved_out;
                    if !ok {
                        return false;
                    }
                    i = self.pos;
                    self.pos = saved;
                } else if self.input[i..].starts_with(b"<?") {
                    let saved = self.pos;
                    let saved_out = self.out.take();
                    self.pos = i;
                    let ok = self.parse_pi();
                    self.out = saved_out;
                    if !ok {
                        return false;
                    }
                    i = self.pos;
                    self.pos = saved;
                } else if self.input[i..].starts_with(b"<!ENTITY") {
                    if !self.validate_internal_entity_decl(i, &mut i) {
                        return false;
                    }
                } else if self.input[i..].starts_with(b"<!ELEMENT")
                    || self.input[i..].starts_with(b"<!ATTLIST")
                {
                    markup_depth = 1;
                    in_notation_decl = false;
                    i += 9;
                } else if self.input[i..].starts_with(b"<!NOTATION") {
                    markup_depth = 1;
                    in_notation_decl = true;
                    i += 10;
                } else {
                    self.emit_error(
                        XmlErrorKind::MalformedDoctype,
                        "unrecognized or malformed declaration inside internal DTD subset",
                        i,
                    );
                    return false;
                }
            } else if b == b'%' {
                self.emit_error(
                    XmlErrorKind::ExternalEntityDisallowed,
                    "parameter entity references and declarations ('%') are disallowed",
                    i,
                );
                return false;
            } else if b == b'>' {
                if markup_depth > 0 {
                    markup_depth -= 1;
                    in_notation_decl = false;
                    i += 1;
                } else {
                    self.emit_error(
                        XmlErrorKind::MalformedDoctype,
                        "unexpected '>' inside internal DTD subset",
                        i,
                    );
                    return false;
                }
            } else {
                if markup_depth > 0
                    && (starts_with_keyword_ci(&self.input[i..], b"SYSTEM")
                        || starts_with_keyword_ci(&self.input[i..], b"PUBLIC"))
                {
                    if in_notation_decl {
                        self.emit_span_error(
                            XmlErrorKind::ExternalEntityDisallowed,
                            "external SYSTEM/PUBLIC notation declarations are disallowed",
                            i,
                            (i + 6).min(len),
                        );
                    } else {
                        self.emit_span_error(
                            XmlErrorKind::MalformedDoctype,
                            "unexpected SYSTEM/PUBLIC keyword inside DTD declaration",
                            i,
                            (i + 6).min(len),
                        );
                    }
                    return false;
                }
                let (cp, char_len) = match decode_utf8_at(self.input, i) {
                    Ok(v) => v,
                    Err(()) => {
                        self.emit_error(
                            XmlErrorKind::InvalidUtf8,
                            "invalid UTF-8 inside <!DOCTYPE>",
                            i,
                        );
                        return false;
                    }
                };
                if !is_xml_char(cp) {
                    self.emit_error(
                        XmlErrorKind::InvalidChar,
                        "illegal XML character inside <!DOCTYPE>",
                        i,
                    );
                    return false;
                }
                i += char_len;
            }
        }

        self.emit_error(
            XmlErrorKind::UnexpectedEof,
            "unterminated <!DOCTYPE> declaration at EOF",
            start,
        );
        false
    }

    fn validate_internal_entity_decl(&mut self, decl_start: usize, cursor: &mut usize) -> bool {
        let len = self.input.len();
        let mut i = decl_start + 8; // after <!ENTITY
        if i >= len || !is_xml_space(self.input[i]) {
            self.emit_error(
                XmlErrorKind::MalformedDoctype,
                "expected whitespace after '<!ENTITY'",
                i,
            );
            return false;
        }
        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if i < len && self.input[i] == b'%' {
            self.emit_error(
                XmlErrorKind::ExternalEntityDisallowed,
                "parameter entity declarations ('<!ENTITY % ...>') are disallowed",
                i,
            );
            return false;
        }
        let name_end = match scan_name(self.input, i) {
            Ok(end) => end,
            Err((XmlErrorKind::InvalidUtf8, off)) => {
                self.emit_error(
                    XmlErrorKind::InvalidUtf8,
                    "invalid UTF-8 in <!ENTITY> name",
                    off,
                );
                return false;
            }
            Err((XmlErrorKind::UnexpectedEof, off)) => {
                self.emit_error(
                    XmlErrorKind::UnexpectedEof,
                    "unterminated <!ENTITY> declaration",
                    off,
                );
                return false;
            }
            Err((_, off)) => {
                self.emit_error(
                    XmlErrorKind::MalformedDoctype,
                    "invalid or nested markup in <!ENTITY> declaration",
                    off,
                );
                return false;
            }
        };
        if self.input[i..name_end].contains(&b':') {
            self.emit_span_error(
                XmlErrorKind::InvalidName,
                "entity name in <!ENTITY> must not contain ':'",
                i,
                name_end,
            );
            return false;
        }
        i = name_end;
        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if starts_with_keyword_ci(&self.input[i..], b"SYSTEM")
            || starts_with_keyword_ci(&self.input[i..], b"PUBLIC")
        {
            self.emit_span_error(
                XmlErrorKind::ExternalEntityDisallowed,
                "external SYSTEM/PUBLIC entity declarations are disallowed (XXE protection)",
                decl_start,
                (i + 6).min(len),
            );
            return false;
        }
        // Scan and strictly validate quoted entity value
        if i >= len || (self.input[i] != b'"' && self.input[i] != b'\'') {
            self.emit_error(
                XmlErrorKind::MalformedDoctype,
                "expected quoted entity value in <!ENTITY>",
                i,
            );
            return false;
        }
        let quote = self.input[i];
        i += 1;
        while i < len && self.input[i] != quote {
            let b = self.input[i];
            if b == b'%' {
                self.emit_error(
                    XmlErrorKind::ExternalEntityDisallowed,
                    "parameter entity reference ('%') is disallowed inside internal <!ENTITY> value",
                    i,
                );
                return false;
            } else if b == b'&' {
                if i + 1 < len && self.input[i + 1] == b'#' {
                    match validate_reference(self.input, i, None) {
                        Ok(next) => {
                            i = next;
                            continue;
                        }
                        Err((k, msg, off)) => {
                            self.emit_error(k, msg, off);
                            return false;
                        }
                    }
                } else {
                    let ref_start = i + 1;
                    let ref_end = match scan_name(self.input, ref_start) {
                        Ok(end) => end,
                        Err((_, off)) => {
                            self.emit_error(
                                XmlErrorKind::InvalidEntityRef,
                                "invalid entity reference inside <!ENTITY> value",
                                off,
                            );
                            return false;
                        }
                    };
                    if ref_end >= len
                        || self.input[ref_end] != b';'
                        || (ref_end - ref_start) > 64
                        || self.input[ref_start..ref_end].contains(&b':')
                    {
                        self.emit_error(
                            XmlErrorKind::InvalidEntityRef,
                            "malformed entity reference inside <!ENTITY> value",
                            i,
                        );
                        return false;
                    }
                    i = ref_end + 1;
                    continue;
                }
            }
            let (cp, char_len) = match decode_utf8_at(self.input, i) {
                Ok(v) => v,
                Err(()) => {
                    self.emit_error(
                        XmlErrorKind::InvalidUtf8,
                        "invalid UTF-8 inside <!ENTITY> value",
                        i,
                    );
                    return false;
                }
            };
            if !is_xml_char(cp) {
                self.emit_error(
                    XmlErrorKind::InvalidChar,
                    format!("illegal XML character U+{:04X} inside <!ENTITY> value", cp),
                    i,
                );
                return false;
            }
            i += char_len;
        }
        if i >= len {
            self.emit_error(
                XmlErrorKind::UnexpectedEof,
                "unterminated entity value in <!ENTITY>",
                decl_start,
            );
            return false;
        }
        i += 1;
        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if i >= len || self.input[i] != b'>' {
            if i < len && self.input[i] == b'%' {
                self.emit_error(
                    XmlErrorKind::ExternalEntityDisallowed,
                    "parameter entity reference ('%') is disallowed in <!ENTITY>",
                    i,
                );
                return false;
            }
            self.emit_error(
                XmlErrorKind::MalformedDoctype,
                "expected '>' to close <!ENTITY> declaration",
                i,
            );
            return false;
        }
        *cursor = i + 1;
        true
    }

    fn parse_start_or_empty_tag(&mut self) -> bool {
        let tag_start = self.pos;
        if self.root_closed {
            self.emit_error(
                XmlErrorKind::MultipleRootElements,
                "only one root element is allowed in an XML document",
                tag_start,
            );
            return false;
        }
        if self.stack.len() >= self.config.max_depth.min(MAX_DEPTH) {
            self.emit_error(
                XmlErrorKind::MaxDepthExceeded,
                format!(
                    "element nesting depth exceeds maximum limit of {}",
                    self.config.max_depth.min(MAX_DEPTH)
                ),
                tag_start,
            );
            return false;
        }

        let name_start = tag_start + 1;
        let name_end = match scan_name(self.input, name_start) {
            Ok(end) => end,
            Err((k, off)) => {
                self.emit_error(k, "invalid element tag name", off);
                return false;
            }
        };
        let raw_name = &self.input[name_start..name_end];
        let (elem_prefix, _elem_local) = match split_and_validate_qname(raw_name) {
            Ok(parts) => parts,
            Err(k) => {
                self.emit_span_error(
                    k,
                    format!(
                        "invalid element QName '{}'",
                        String::from_utf8_lossy(raw_name)
                    ),
                    name_start,
                    name_end,
                );
                return false;
            }
        };
        if raw_name == b"xmlns" || elem_prefix == Some(b"xmlns") {
            self.emit_span_error(
                XmlErrorKind::InvalidNamespaceDeclaration,
                "element name must not be 'xmlns' or use the 'xmlns' prefix",
                name_start,
                name_end,
            );
            return false;
        }

        let parent_preserve = self.current_preserve_whitespace();
        let parent_inline = self.stack.last().is_some_and(|f| f.inline_mode);
        if let Some(parent) = self.stack.last_mut() {
            parent.has_child_elements = true;
        }

        // Buffer attributes on this tag
        let mut attrs: Vec<BufferedAttr<'a>> = Vec::new();
        self.raw_attr_set.clear();

        let mut i = name_end;
        let len = self.input.len();
        let mut is_empty_element = false;

        loop {
            let ws_start = i;
            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            let had_ws = i > ws_start;

            if i >= len {
                self.emit_error(
                    XmlErrorKind::UnexpectedEof,
                    "unterminated start tag at EOF",
                    tag_start,
                );
                return false;
            }
            if self.input[i] == b'>' {
                i += 1;
                break;
            }
            if self.input[i] == b'/' {
                if i + 1 < len && self.input[i + 1] == b'>' {
                    is_empty_element = true;
                    i += 2;
                    break;
                }
                self.emit_error(
                    XmlErrorKind::UnexpectedChar,
                    "expected '>' immediately after '/' in empty-element tag",
                    i,
                );
                return false;
            }
            if !had_ws {
                self.emit_error(
                    XmlErrorKind::UnexpectedChar,
                    "whitespace is required before attribute name in start tag",
                    i,
                );
                return false;
            }

            let attr_name_start = i;
            let attr_name_end = match scan_name(self.input, attr_name_start) {
                Ok(end) => end,
                Err((k, off)) => {
                    self.emit_error(k, "invalid attribute name", off);
                    return false;
                }
            };
            let attr_raw_name = &self.input[attr_name_start..attr_name_end];
            let (attr_prefix, attr_local) = match split_and_validate_qname(attr_raw_name) {
                Ok(parts) => parts,
                Err(k) => {
                    self.emit_span_error(
                        k,
                        format!(
                            "invalid attribute QName '{}'",
                            String::from_utf8_lossy(attr_raw_name)
                        ),
                        attr_name_start,
                        attr_name_end,
                    );
                    return false;
                }
            };

            if !self.raw_attr_set.insert(attr_raw_name) {
                self.emit_span_error(
                    XmlErrorKind::DuplicateAttribute,
                    format!(
                        "duplicate attribute '{}' on element '<{}>'",
                        String::from_utf8_lossy(attr_raw_name),
                        String::from_utf8_lossy(raw_name)
                    ),
                    attr_name_start,
                    attr_name_end,
                );
                return false;
            }

            i = attr_name_end;
            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            if i >= len || self.input[i] != b'=' {
                self.emit_error(
                    XmlErrorKind::UnexpectedChar,
                    "expected '=' after attribute name",
                    i,
                );
                return false;
            }
            i += 1;
            while i < len && is_xml_space(self.input[i]) {
                i += 1;
            }
            if i >= len || (self.input[i] != b'"' && self.input[i] != b'\'') {
                self.emit_error(
                    XmlErrorKind::UnexpectedChar,
                    "attribute value must be enclosed in single or double quotes",
                    i,
                );
                return false;
            }
            let quote = self.input[i];
            let val_offset = i + 1;
            let (after_quote, raw_value) = match scan_attribute_value(self.input, val_offset, quote)
            {
                Ok(v) => v,
                Err((k, msg, off)) => {
                    self.emit_error(k, msg, off);
                    return false;
                }
            };
            i = after_quote;

            attrs.push(BufferedAttr {
                raw_name: attr_raw_name,
                prefix: attr_prefix,
                local_name: attr_local,
                raw_value,
                quote,
                name_offset: attr_name_start,
                value_offset: val_offset,
            });
        }

        let tag_end = i;
        let (open_line, open_col) = line_col_at(self.input, tag_start);
        let inherited_default_ns = self
            .stack
            .last()
            .map(|f| f.default_ns.clone())
            .unwrap_or(Cow::Borrowed(b""));
        let mut frame = XmlFrame {
            raw_name,
            open_offset: tag_start,
            open_line,
            open_col,
            default_ns: inherited_default_ns,
            ns_bindings: Vec::new(),
            ns_map: None,
            xml_space_preserve: parent_preserve,
            has_child_elements: false,
            has_non_ws_text: false,
            inline_mode: parent_preserve || parent_inline,
        };

        // Pass 1 over buffered attributes: apply xmlns / xmlns:prefix bindings and xml:space
        for attr in &attrs {
            if attr.raw_name == b"xmlns" {
                let uri = resolve_attr_value(attr.raw_value);
                if uri.as_ref() == XML_NS_URI || uri.as_ref() == XMLNS_NS_URI {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        "default namespace cannot be bound to the reserved 'xml' or 'xmlns' namespace URI",
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                frame.default_ns = uri;
            } else if attr.prefix == Some(b"xmlns") {
                let prefix = attr.local_name;
                let uri = resolve_attr_value(attr.raw_value);
                if prefix == b"xmlns" {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        "prefix 'xmlns' is reserved and must not be declared",
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                if uri.is_empty() {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        format!(
                            "namespace prefix '{}' cannot be bound to an empty URI in Namespaces in XML 1.0",
                            String::from_utf8_lossy(prefix)
                        ),
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                if prefix == b"xml" && uri.as_ref() != XML_NS_URI {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        "prefix 'xml' may only be bound to 'http://www.w3.org/XML/1998/namespace'",
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                if prefix != b"xml" && uri.as_ref() == XML_NS_URI {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        "only the 'xml' prefix may be bound to 'http://www.w3.org/XML/1998/namespace'",
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                if uri.as_ref() == XMLNS_NS_URI {
                    self.emit_span_error(
                        XmlErrorKind::InvalidNamespaceDeclaration,
                        "no prefix may be bound to 'http://www.w3.org/2000/xmlns/'",
                        attr.name_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
                frame.insert_ns_binding(prefix, uri);
            } else if attr.raw_name == b"xml:space" {
                let val = resolve_attr_value(attr.raw_value);
                if val.as_ref() == b"preserve" {
                    frame.xml_space_preserve = true;
                    frame.inline_mode = true;
                } else if val.as_ref() == b"default" {
                    frame.xml_space_preserve = false;
                    frame.inline_mode = false;
                } else {
                    self.emit_span_error(
                        XmlErrorKind::InvalidXmlSpace,
                        format!(
                            "invalid xml:space value '{}'; must be \"default\" or \"preserve\"",
                            String::from_utf8_lossy(&val)
                        ),
                        attr.value_offset,
                        attr.value_offset + attr.raw_value.len(),
                    );
                    return false;
                }
            }
        }

        // Validate element's own prefix (if any)
        if let Some(ep) = elem_prefix {
            if self.lookup_prefix(ep, &frame).is_none() {
                self.emit_span_error(
                    XmlErrorKind::UndeclaredPrefix,
                    format!(
                        "undeclared namespace prefix '{}' on element '<{}>'",
                        String::from_utf8_lossy(ep),
                        String::from_utf8_lossy(raw_name)
                    ),
                    name_start,
                    name_end,
                );
                return false;
            }
        }

        // Pass 2 over buffered attributes: validate prefixed attribute bindings & expanded {uri}local uniqueness
        self.expanded_attr_set.clear();
        for attr in &attrs {
            if attr.raw_name == b"xmlns" || attr.prefix == Some(b"xmlns") {
                continue;
            }
            if let Some(ap) = attr.prefix {
                let Some(uri) = self.lookup_prefix(ap, &frame) else {
                    self.emit_span_error(
                        XmlErrorKind::UndeclaredPrefix,
                        format!(
                            "undeclared namespace prefix '{}' on attribute '{}'",
                            String::from_utf8_lossy(ap),
                            String::from_utf8_lossy(attr.raw_name)
                        ),
                        attr.name_offset,
                        attr.name_offset + attr.raw_name.len(),
                    );
                    return false;
                };
                if !self
                    .expanded_attr_set
                    .insert((uri.clone(), attr.local_name))
                {
                    self.emit_span_error(
                        XmlErrorKind::DuplicateExpandedAttribute,
                        format!(
                            "expanded attribute '{{{}}}{}' is duplicated on element '<{}>'",
                            String::from_utf8_lossy(&uri),
                            String::from_utf8_lossy(attr.local_name),
                            String::from_utf8_lossy(raw_name)
                        ),
                        attr.name_offset,
                        attr.name_offset + attr.raw_name.len(),
                    );
                    return false;
                }
            }
        }

        // Bounded lookahead for mixed content or inline leaf when formatting
        if self.out.is_some()
            && !is_empty_element
            && !frame.inline_mode
            && self.lookahead_is_inline_or_mixed(tag_end, raw_name, self.stack.len())
        {
            frame.inline_mode = true;
        }

        // Stream formatted output for this start/empty tag if enabled
        if self.out.is_some() {
            let depth = self.stack.len();
            if !parent_preserve
                && !parent_inline
                && depth > 0
                && !self.write_indent(depth, tag_start)
            {
                return false;
            }
            if !self.write_bytes(b"<", tag_start) || !self.write_bytes(raw_name, tag_start) {
                return false;
            }
            if self.config.sort_attributes && attrs.len() > 1 {
                attrs.sort_unstable_by(|a, b| a.raw_name.cmp(b.raw_name));
            }
            for attr in &attrs {
                let q = [attr.quote];
                if !self.write_bytes(b" ", attr.name_offset)
                    || !self.write_bytes(attr.raw_name, attr.name_offset)
                    || !self.write_bytes(b"=", attr.name_offset)
                    || !self.write_bytes(&q, attr.value_offset)
                    || !self.write_bytes(attr.raw_value, attr.value_offset)
                    || !self.write_bytes(&q, attr.value_offset)
                {
                    return false;
                }
            }
            if is_empty_element {
                if !self.write_bytes(b"/>", tag_start) {
                    return false;
                }
                if !parent_preserve && !parent_inline && !self.write_bytes(b"\n", tag_start) {
                    return false;
                }
            } else {
                if !self.write_bytes(b">", tag_start) {
                    return false;
                }
                if !frame.inline_mode && !self.write_bytes(b"\n", tag_start) {
                    return false;
                }
            }
        }

        self.seen_root = true;
        self.pos = tag_end;
        if is_empty_element {
            if self.stack.is_empty() {
                self.root_closed = true;
            }
        } else {
            self.stack.push(frame);
        }
        true
    }

    fn parse_end_tag(&mut self) -> bool {
        let tag_start = self.pos;
        let name_start = tag_start + 2;
        let name_end = match scan_name(self.input, name_start) {
            Ok(end) => end,
            Err((k, off)) => {
                self.emit_error(k, "invalid closing tag name", off);
                return false;
            }
        };
        let raw_name = &self.input[name_start..name_end];
        let mut i = name_end;
        let len = self.input.len();
        while i < len && is_xml_space(self.input[i]) {
            i += 1;
        }
        if i >= len || self.input[i] != b'>' {
            self.emit_error(
                XmlErrorKind::UnexpectedChar,
                "expected '>' in closing tag",
                i,
            );
            return false;
        }
        let tag_end = i + 1;

        let Some(frame) = self.stack.pop() else {
            self.emit_span_error(
                XmlErrorKind::MismatchedClosingTag,
                format!(
                    "unexpected closing tag '</{}>' with no matching open element",
                    String::from_utf8_lossy(raw_name)
                ),
                tag_start,
                tag_end,
            );
            return false;
        };

        if frame.raw_name != raw_name {
            self.emit_span_error(
                XmlErrorKind::MismatchedClosingTag,
                format!(
                    "mismatched closing tag '</{}>'; expected '</{}>' (opened at {}:{})",
                    String::from_utf8_lossy(raw_name),
                    String::from_utf8_lossy(frame.raw_name),
                    frame.open_line,
                    frame.open_col
                ),
                tag_start,
                tag_end,
            );
            return false;
        }

        if self.out.is_some() {
            let depth = self.stack.len();
            let parent_preserve = self.current_preserve_whitespace();
            let parent_inline = self.stack.last().is_some_and(|f| f.inline_mode);

            if !frame.inline_mode
                && !frame.xml_space_preserve
                && !self.write_indent(depth, tag_start)
            {
                return false;
            }
            if !self.write_bytes(b"</", tag_start)
                || !self.write_bytes(raw_name, tag_start)
                || !self.write_bytes(b">", tag_start)
            {
                return false;
            }
            if !parent_preserve && !parent_inline && !self.write_bytes(b"\n", tag_start) {
                return false;
            }
        }

        self.pos = tag_end;
        if self.stack.is_empty() {
            self.root_closed = true;
        }
        true
    }

    fn parse_text_content(&mut self) -> bool {
        let start = self.pos;
        let len = self.input.len();
        let mut i = start;
        let mut has_non_ws = false;

        while i < len {
            let fast = skip_xml_text_bytes(&self.input[i..]);
            if fast > 0 {
                if !has_non_ws {
                    for &b in &self.input[i..i + fast] {
                        if !is_xml_space(b) {
                            has_non_ws = true;
                            break;
                        }
                    }
                }
                i += fast;
                if i >= len {
                    break;
                }
            }

            let b = self.input[i];
            if b == b'<' {
                break;
            } else if b == b'&' {
                has_non_ws = true;
                match validate_reference(self.input, i, None) {
                    Ok(next) => i = next,
                    Err((k, msg, off)) => {
                        self.emit_error(k, msg, off);
                        return false;
                    }
                }
            } else if b == b']' {
                if !has_non_ws {
                    has_non_ws = true;
                }
                if i + 2 < len && self.input[i + 1] == b']' && self.input[i + 2] == b'>' {
                    self.emit_span_error(
                        XmlErrorKind::CdataEndInText,
                        "the character sequence ']]>' is not permitted in XML character data",
                        i,
                        i + 3,
                    );
                    return false;
                }
                i += 1;
            } else if b == b'\r' {
                i += 1;
            } else if b < 0x20 {
                self.emit_error(
                    XmlErrorKind::InvalidChar,
                    format!("illegal control character 0x{:02X} in character data", b),
                    i,
                );
                return false;
            } else {
                let (cp, char_len) = match decode_utf8_at(self.input, i) {
                    Ok(v) => v,
                    Err(()) => {
                        self.emit_error(
                            XmlErrorKind::InvalidUtf8,
                            "invalid UTF-8 byte sequence in character data",
                            i,
                        );
                        return false;
                    }
                };
                if !is_xml_char(cp) {
                    self.emit_error(
                        XmlErrorKind::InvalidChar,
                        format!("character U+{:04X} is not a valid XML 1.0 Char", cp),
                        i,
                    );
                    return false;
                }
                if !has_non_ws {
                    has_non_ws = true;
                }
                i += char_len;
            }
        }

        if self.stack.is_empty() {
            if has_non_ws {
                self.emit_span_error(
                    XmlErrorKind::ContentOutsideRoot,
                    "character data is not permitted outside the root element",
                    start,
                    i,
                );
                return false;
            }
            self.pos = i;
            return true;
        }

        if has_non_ws {
            if let Some(top) = self.stack.last_mut() {
                top.has_non_ws_text = true;
            }
        }

        if self.out.is_some() {
            let preserve = self.current_preserve_whitespace();
            let inline = self.stack.last().is_some_and(|f| f.inline_mode);
            let slice = &self.input[start..i];
            if preserve {
                if !self.write_bytes(slice, start) {
                    return false;
                }
            } else if inline {
                if (has_non_ws || !slice.iter().any(|&b| b == b'\n' || b == b'\r'))
                    && !self.write_bytes(slice, start)
                {
                    return false;
                }
            } else if has_non_ws {
                let depth = self.stack.len();
                let trimmed = trim_xml_ascii_ws(slice);
                if !self.write_indent(depth, start)
                    || !self.write_bytes(trimmed, start)
                    || !self.write_bytes(b"\n", start)
                {
                    return false;
                }
            }
        }

        self.pos = i;
        true
    }

    fn lookup_prefix<'b>(
        &'b self,
        prefix: &[u8],
        current_frame: &'b XmlFrame<'a>,
    ) -> Option<Cow<'a, [u8]>> {
        if prefix == b"xml" {
            return Some(Cow::Borrowed(XML_NS_URI));
        }
        if let Some(uri) = current_frame.get_ns_binding(prefix) {
            return Some(uri.clone());
        }
        for frame in self.stack.iter().rev() {
            if let Some(uri) = frame.get_ns_binding(prefix) {
                return Some(uri.clone());
            }
        }
        None
    }

    #[inline]
    fn current_preserve_whitespace(&self) -> bool {
        self.stack.last().is_some_and(|f| f.xml_space_preserve)
    }

    /// Bounded lookahead after `<tag>` to detect mixed content (sibling non-ws text + child elements)
    /// or inline leaf elements fitting within `config.line_width`.
    fn lookahead_is_inline_or_mixed(
        &self,
        after_open_tag: usize,
        raw_name: &[u8],
        depth: usize,
    ) -> bool {
        let max_window = 512usize.min(self.input.len().saturating_sub(after_open_tag));
        let window = &self.input[after_open_tag..after_open_tag + max_window];

        let mut i = 0;
        let mut saw_non_ws_text = false;
        let mut saw_child_tag = false;
        let mut saw_newline = false;
        let mut nested_depth = 0usize;

        while i < window.len() {
            let b = window[i];
            if b == b'<' {
                if window[i..].starts_with(b"<!--") || window[i..].starts_with(b"<?") {
                    return false;
                }
                if window[i..].starts_with(b"<![CDATA[") {
                    if nested_depth == 0 {
                        saw_non_ws_text = true;
                    }
                    if let Some(end) = find_subslice(&window[i + 9..], b"]]>") {
                        i += 9 + end + 3;
                        continue;
                    }
                    return nested_depth == 0;
                }
                if i + 1 < window.len() && window[i + 1] == b'/' {
                    if nested_depth == 0 {
                        if saw_non_ws_text && saw_child_tag {
                            return true; // Mixed content
                        }
                        if !saw_child_tag {
                            let indent_cols = depth.saturating_mul(self.config.indent_width);
                            let total_cols = indent_cols
                                .saturating_add(raw_name.len() * 2 + 5)
                                .saturating_add(i);
                            if !saw_newline && total_cols <= self.config.line_width {
                                return true; // Inline leaf element
                            }
                            if saw_non_ws_text && !saw_newline {
                                return true;
                            }
                        }
                        return false;
                    }
                    nested_depth -= 1;
                } else {
                    saw_child_tag = true;
                    if saw_non_ws_text {
                        return true; // Mixed content!
                    }
                    nested_depth += 1;
                }
                while i < window.len() && window[i] != b'>' {
                    if i + 1 < window.len() && window[i] == b'/' && window[i + 1] == b'>' {
                        nested_depth = nested_depth.saturating_sub(1);
                    }
                    i += 1;
                }
                i += 1;
            } else {
                if b == b'\n' || b == b'\r' {
                    if nested_depth == 0 {
                        saw_newline = true;
                    }
                } else if !is_xml_space(b) && nested_depth == 0 {
                    saw_non_ws_text = true;
                    if saw_child_tag {
                        return true; // Mixed content!
                    }
                }
                i += 1;
            }
        }
        saw_non_ws_text && saw_child_tag
    }
}

fn trim_xml_ascii_ws(mut s: &[u8]) -> &[u8] {
    while let Some(&first) = s.first() {
        if is_xml_space(first) {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = s.last() {
        if is_xml_space(last) {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
