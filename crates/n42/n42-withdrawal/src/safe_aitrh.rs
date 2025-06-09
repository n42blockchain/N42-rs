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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ArithError {
    Overflow,
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

    assign_method!(safe_add_assign, safe_add, Rhs, "+=");
    assign_method!(safe_sub_assign, safe_sub, Rhs, "-=");
    assign_method!(safe_rem_assign, safe_rem, Rhs, "%=");
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

        }
    };
}

impl_safe_arith!(u64);
impl_safe_arith!(usize);