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
