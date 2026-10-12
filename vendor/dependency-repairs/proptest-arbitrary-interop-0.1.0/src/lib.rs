//! # proptest-arbitrary-interop
//!
//! This crate provides the necessary glue to reuse an implementation of
//! [`arbitrary::Arbitrary`] as a [`proptest::strategy::Strategy`].
//!
//! # Usage
//!
//! in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! arbitrary = "1.1.3"
//! proptest  = "1.0.0"
//! ```
//!
//! In your code:
//!
//! ```rust
//!
//! // Part 1: suppose you implement Arbitrary for one of your types
//! // because you want to fuzz it.
//!
//! use arbitrary::{Arbitrary, Result, Unstructured};
//! #[derive(Copy, Clone, Debug)]
//! pub struct Rgb {
//!     pub r: u8,
//!     pub g: u8,
//!     pub b: u8,
//! }
//! impl<'a> Arbitrary<'a> for Rgb {
//!     fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
//!         let r = u8::arbitrary(u)?;
//!         let g = u8::arbitrary(u)?;
//!         let b = u8::arbitrary(u)?;
//!         Ok(Rgb { r, g, b })
//!     }
//! }
//!
//! // Part 2: suppose you later decide that in addition to fuzzing
//! // you want to use that Arbitrary impl, but with proptest.
//!
//! use proptest::prelude::*;
//! use proptest_arbitrary_interop::arb;
//!
//! proptest! {
//!     #[test]
//!     #[should_panic]
//!     fn always_red(color in arb::<Rgb>()) {
//!         prop_assert!(color.g == 0 || color.r > color.g);
//!     }
//! }
//! ```
//!
//! # Caveats
//!
//! It only works with types that implement [`arbitrary::Arbitrary`] in a
//! particular fashion: those conforming to the requirements of [`ArbInterop`].
//! These are roughly "types that, when randomly-generated, don't retain
//! pointers into the random-data buffer wrapped by the
//! [`arbitrary::Unstructured`] they are generated from". Many implementations
//! of [`arbitrary::Arbitrary`] will fit the bill, but certain kinds of
//! "zero-copy" implementations of [`arbitrary::Arbitrary`] will not work. This
//! requirement appears to be a necessary part of the semantic model of
//! [`proptest`] -- generated values have to own their pointer graph, no
//! borrows. Patches welcome if you can figure out a way to not require it.
//!
//! This crate is based on
//! [`proptest-quickcheck-interop`](https://crates.io/crates/proptest-quickcheck-interop)
//! by Mazdak Farrokhzad, without whose work I wouldn't have had a clue how to
//! approach this. The exact type signatures for the [`ArbInterop`] type are
//! courtesy of Jim Blandy, who I hereby officially designate for-all-time as
//! the Rust Puzzle King. Any errors I've introduced along the way are, of
//! course, my own.

use arbitrary;
use proptest;

use core::fmt::Debug;
use proptest::prelude::{Rng, RngCore};
use proptest::test_runner::TestRunner;
use std::marker::PhantomData;

/// The subset of possible [`arbitrary::Arbitrary`] implementations that this
/// crate works with. The main concern here is the `for<'a> Arbitrary<'a>`
/// business, which (in practice) decouples the generated `Arbitrary` value from
/// the lifetime of the random buffer it's fed; I can't actually explain how,
/// because Rust's type system is way over my head.
pub trait ArbInterop: for<'a> arbitrary::Arbitrary<'a> + 'static + Debug + Clone {}
impl<A: for<'a> arbitrary::Arbitrary<'a> + 'static + Debug + Clone> ArbInterop for A {}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ArbStrategy<A: ArbInterop> {
    __ph: PhantomData<A>,
    size: usize,
}

#[derive(Debug)]
pub struct ArbValueTree<A: Debug> {
    bytes: Vec<u8>,
    curr: A,
    prev: Option<A>,
    next: usize,
}

impl<A: ArbInterop> proptest::strategy::ValueTree for ArbValueTree<A> {
    type Value = A;

    fn current(&self) -> Self::Value {
        self.curr.clone()
    }

    fn complicate(&mut self) -> bool {
        // We can only complicate if we previously simplified. Complicating
        // twice in a row without interleaved simplification is guaranteed to
        // always yield false for the second call.
        if let Some(prev) = self.prev.take() {
            // Throw away the current value!
            self.curr = prev;
            true
        } else {
            false
        }
    }

    fn simplify(&mut self) -> bool {
        if self.next == 0 {
            return false;
        }
        self.next -= 1;
        if let Ok(simpler) = Self::gen_one_with_size(&self.bytes, self.next) {
            // Throw away the previous value and set the current value as prev.
            // Advance the iterator and set the current value to the next one.
            self.prev = Some(core::mem::replace(&mut self.curr, simpler));
            true
        } else {
            false
        }
    }
}

impl<A: ArbInterop> ArbStrategy<A> {
    pub fn new(size: usize) -> Self {
        Self {
            __ph: PhantomData,
            size,
        }
    }
}

impl<A: ArbInterop> ArbValueTree<A> {
    fn gen_one_with_size(bytes: &[u8], size: usize) -> Result<A, arbitrary::Error> {
        let mut unstructured = arbitrary::Unstructured::new(&bytes[0..size]);
        A::arbitrary(&mut unstructured)
    }

    pub fn new(bytes: Vec<u8>) -> Result<Self, arbitrary::Error> {
        let next = bytes.len();
        let curr = Self::gen_one_with_size(&bytes, next)?;
        Ok(Self {
            bytes,
            prev: None,
            curr,
            next,
        })
    }
}

impl<A: ArbInterop> proptest::strategy::Strategy for ArbStrategy<A> {
    type Tree = ArbValueTree<A>;
    type Value = A;

    fn new_tree(&self, runner: &mut TestRunner) -> proptest::strategy::NewTree<Self> {
        let mut bytes = std::iter::repeat(0u8).take(self.size).collect::<Vec<u8>>();
        runner.rng().fill_bytes(&mut bytes);
        ArbValueTree::new(bytes).map_err(|_| "initial arbitrary call failed".into())
    }
}

/// Constructs a [`proptest::strategy::Strategy`] for a given
/// [`arbitrary::Arbitrary`] type, generating `size` bytes of random data as
/// input to the [`arbitrary::Arbitrary`] type.
pub fn arb_sized<A: ArbInterop>(size: usize) -> ArbStrategy<A> {
    ArbStrategy::new(size)
}

/// Default size (256) passed to [`arb_sized`](crate::arb_sized) by
/// [`arb`](crate::arb).
pub const DEFAULT_SIZE: usize = 256;

/// Calls [`arb_sized`](crate::arb_sized) with
/// [`DEFAULT_SIZE`](crate::DEFAULT_SIZE) which is `256`.
pub fn arb<A: ArbInterop>() -> ArbStrategy<A> {
    arb_sized(DEFAULT_SIZE)
}
