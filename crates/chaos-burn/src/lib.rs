//! CA-PQ `chaos-burn`: volatile memory wipe (12 lines, zero dependencies).
//!
//! The single audited `unsafe` in the tree. Rationale: secret wiping requires
//! stores the optimizer cannot delete as dead. Only volatile (or atomic)
//! stores qualify; atomics-from-`&mut` are unavailable on our toolchain, so a
//! volatile byte write it is. Everything else in the workspace keeps
//! `forbid(unsafe_code)`.

#![no_std]
#![deny(unsafe_code)]

/// Overwrite `buf` with zeros through volatile stores plus a compiler fence.
#[allow(unsafe_code)]
pub fn burn(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live exclusive `&mut u8`; a volatile write of `0`
        // to a valid, aligned byte is always sound. No reads, no aliasing,
        // no pointer arithmetic.
        unsafe {
            core::ptr::write_volatile(b, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Overwrite an `i16` slice (secret polynomials) with zeros, same guarantee.
#[allow(unsafe_code)]
pub fn burn_words(buf: &mut [i16]) {
    for w in buf.iter_mut() {
        // SAFETY: same argument as `burn`: exclusive `&mut`, aligned, no reads.
        unsafe {
            core::ptr::write_volatile(w, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zeroes() {
        let mut b = [0xAAu8; 64];
        burn(&mut b);
        assert_eq!(b, [0u8; 64]);
        let mut e: [u8; 0] = [];
        burn(&mut e);
        let mut w = [0x1234i16; 16];
        burn_words(&mut w);
        assert_eq!(w, [0i16; 16]);
    }
}
