# proptest-arbitrary-interop

This crate provides the necessary glue to reuse an implementation of
[`arbitrary::Arbitrary`] as a [`proptest::strategy::Strategy`].

## Usage

in `Cargo.toml`:

```toml
[dependencies]
arbitrary = "1.1.3"
proptest  = "1.0.0"
```

In your code:

```rust

// Part 1: suppose you implement Arbitrary for one of your types
// because you want to fuzz it.

use arbitrary::{Arbitrary, Result, Unstructured};
#[derive(Copy, Clone, Debug)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}
impl<'a> Arbitrary<'a> for Rgb {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let r = u8::arbitrary(u)?;
        let g = u8::arbitrary(u)?;
        let b = u8::arbitrary(u)?;
        Ok(Rgb { r, g, b })
    }
}

// Part 2: suppose you later decide that in addition to fuzzing
// you want to use that Arbitrary impl, but with proptest.

use proptest::prelude::*;
use proptest_arbitrary_interop::arb;

proptest! {
    #[test]
    #[should_panic]
    fn always_red(color in arb::<Rgb>()) {
        prop_assert!(color.g == 0 || color.r > color.g);
    }
}
```

## Caveats

It only works with types that implement [`arbitrary::Arbitrary`] in a
particular fashion: those conforming to the requirements of [`ArbInterop`].
These are roughly "types that, when randomly-generated, don't retain
pointers into the random-data buffer wrapped by the
[`arbitrary::Unstructured`] they are generated from". Many implementations
of [`arbitrary::Arbitrary`] will fit the bill, but certain kinds of
"zero-copy" implementations of [`arbitrary::Arbitrary`] will not work. This
requirement appears to be a necessary part of the semantic model of
[`proptest`] -- generated values have to own their pointer graph, no
borrows. Patches welcome if you can figure out a way to not require it.

This crate is based on
[`proptest-quickcheck-interop`](https://crates.io/crates/proptest-quickcheck-interop)
by Mazdak Farrokhzad, without whose work I wouldn't have had a clue how to
approach this. The exact type signatures for the [`ArbInterop`] type are
courtesy of Jim Blandy, who I hereby officially designate for-all-time as
the Rust Puzzle King. Any errors I've introduced along the way are, of
course, my own.

License: MIT OR Apache-2.0
