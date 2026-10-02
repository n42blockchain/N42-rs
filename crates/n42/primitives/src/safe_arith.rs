// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Extension trait for iterators, providing a safe replacement for `sum`.
pub trait SafeArithIter<T> {
    fn safe_sum(self) -> Result<T>;
}

impl<I, T> SafeArithIter<T> for I
where
    I: Iterator<Item = T> + Sized,
    T: SafeArith,
{
    fn safe_sum(mut self) -> Result<T> {
        self.try_fold(T::ZERO, |acc, x| acc.safe_add(x))
    }
}

/// Error representing the failure of an arithmetic operation.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum ArithError {
    #[error("overflow")]
    Overflow,
    #[error("divide by zero")]
    DivisionByZero,
}

pub type Result<T> = std::result::Result<T, ArithError>;

macro_rules! assign_method {
    ($name:ident, $op:ident, $doc_op:expr) => {
        assign_method!($name, $op, Self, $doc_op);
    };
    ($name:ident, $op:ident, $rhs_ty:ty, $doc_op:expr) => {
        #[doc = "Safe variant of `"]
        #[doc = $doc_op]
        #[doc = "`."]
        #[inline]
        fn $name(&mut self, other: $rhs_ty) -> Result<()> {
            *self = self.$op(other)?;
            Ok(())
        }
    };
}

/// Trait providing safe arithmetic operations for built-in types.
pub trait SafeArith<Rhs = Self>: Sized + Copy {
    const ZERO: Self;
    const ONE: Self;

    /// Safe variant of `+` that guards against overflow.
    fn safe_add(&self, other: Rhs) -> Result<Self>;

    /// Safe variant of `-` that guards against overflow.
    fn safe_sub(&self, other: Rhs) -> Result<Self>;

    /// Safe variant of `%` that guards against division by 0.
    fn safe_rem(&self, other: Rhs) -> Result<Self>;

    /// Safe variant of `/` that guards against division by 0.
    fn safe_div(&self, other: Rhs) -> Result<Self>;

    /// Safe variant of `*` that guards against overflow.
    fn safe_mul(&self, other: Rhs) -> Result<Self>;

    assign_method!(safe_add_assign, safe_add, Rhs, "+=");
    assign_method!(safe_sub_assign, safe_sub, Rhs, "-=");
    assign_method!(safe_rem_assign, safe_rem, Rhs, "%=");
    assign_method!(safe_div_assign, safe_div, Rhs, "/=");
    assign_method!(safe_mul_assign, safe_mul, Rhs, "*=");
}

macro_rules! impl_safe_arith {
    ($typ:ty) => {
        impl SafeArith for $typ {
            const ZERO: Self = 0;
            const ONE: Self = 1;

            #[inline]
            fn safe_add(&self, other: Self) -> Result<Self> {
                self.checked_add(other).ok_or(ArithError::Overflow)
            }

            #[inline]
            fn safe_sub(&self, other: Self) -> Result<Self> {
                self.checked_sub(other).ok_or(ArithError::Overflow)
            }

            #[inline]
            fn safe_rem(&self, other: Self) -> Result<Self> {
                self.checked_rem(other).ok_or(ArithError::DivisionByZero)
            }

            #[inline]
            fn safe_div(&self, other: Self) -> Result<Self> {
                self.checked_div(other).ok_or(ArithError::DivisionByZero)
            }

            #[inline]
            fn safe_mul(&self, other: Self) -> Result<Self> {
                self.checked_mul(other).ok_or(ArithError::Overflow)
            }
        }
    };
}

impl_safe_arith!(u64);
impl_safe_arith!(usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_overflow_is_detected() {
        assert_eq!(1u64.safe_add(2), Ok(3));
        assert_eq!(u64::MAX.safe_add(1), Err(ArithError::Overflow));
        assert_eq!(usize::MAX.safe_add(1), Err(ArithError::Overflow));
        assert_eq!((u64::MAX - 1).safe_add(1), Ok(u64::MAX));
    }

    #[test]
    fn sub_underflow_is_detected() {
        assert_eq!(5u64.safe_sub(5), Ok(0));
        assert_eq!(0u64.safe_sub(1), Err(ArithError::Overflow));
        assert_eq!(0usize.safe_sub(1), Err(ArithError::Overflow));
    }

    #[test]
    fn mul_overflow_is_detected() {
        assert_eq!(6u64.safe_mul(7), Ok(42));
        assert_eq!(u64::MAX.safe_mul(2), Err(ArithError::Overflow));
        assert_eq!(u64::MAX.safe_mul(0), Ok(0));
        assert_eq!(usize::MAX.safe_mul(2), Err(ArithError::Overflow));
    }

    #[test]
    fn div_and_rem_by_zero_are_detected() {
        assert_eq!(10u64.safe_div(3), Ok(3));
        assert_eq!(10u64.safe_rem(3), Ok(1));
        assert_eq!(10u64.safe_div(0), Err(ArithError::DivisionByZero));
        assert_eq!(10u64.safe_rem(0), Err(ArithError::DivisionByZero));
        assert_eq!(10usize.safe_div(0), Err(ArithError::DivisionByZero));
        assert_eq!(10usize.safe_rem(0), Err(ArithError::DivisionByZero));
    }

    #[test]
    fn assign_variants_update_in_place_only_on_success() {
        let mut x = 10u64;
        x.safe_add_assign(5).unwrap();
        assert_eq!(x, 15);
        x.safe_sub_assign(3).unwrap();
        assert_eq!(x, 12);
        x.safe_mul_assign(2).unwrap();
        assert_eq!(x, 24);
        x.safe_div_assign(5).unwrap();
        assert_eq!(x, 4);
        x.safe_rem_assign(3).unwrap();
        assert_eq!(x, 1);

        // A failing assignment leaves the value untouched.
        assert_eq!(x.safe_sub_assign(2), Err(ArithError::Overflow));
        assert_eq!(x, 1);
        assert_eq!(x.safe_div_assign(0), Err(ArithError::DivisionByZero));
        assert_eq!(x, 1);
        assert_eq!(x.safe_rem_assign(0), Err(ArithError::DivisionByZero));
        assert_eq!(x, 1);
        let mut y = u64::MAX;
        assert_eq!(y.safe_add_assign(1), Err(ArithError::Overflow));
        assert_eq!(y.safe_mul_assign(2), Err(ArithError::Overflow));
        assert_eq!(y, u64::MAX);
    }

    #[test]
    fn constants_and_error_display() {
        assert_eq!(<u64 as SafeArith>::ZERO, 0);
        assert_eq!(<usize as SafeArith>::ONE, 1);
        assert_eq!(ArithError::Overflow.to_string(), "overflow");
        assert_eq!(ArithError::DivisionByZero.to_string(), "divide by zero");
    }

    #[test]
    fn safe_sum_adds_and_reports_overflow() {
        assert_eq!(Vec::<u64>::new().into_iter().safe_sum(), Ok(0));
        assert_eq!([1u64, 2, 3].into_iter().safe_sum(), Ok(6));
        assert_eq!([u64::MAX, 1].into_iter().safe_sum(), Err(ArithError::Overflow));
        assert_eq!([usize::MAX, 0].into_iter().safe_sum(), Ok(usize::MAX));
    }
}
