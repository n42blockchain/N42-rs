// Copyright (c) 2017-2025 N42 Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One reading of the `N42_*` environment knobs.
//!
//! Before this crate every knob parsed its own value: most switches tested
//! `== "1"`, default-on ones `!= "0"`, and fifteen enabled on any value at
//! all, so `NAME=0` turned them *on* (`docs/KNOBS.md` notes 4-5). Three
//! functions replace those readers:
//!
//! - [`flag`]: a switch. On is `1|true|on|yes`, off is `0|false|off|no` or
//!   the empty string (case-insensitive, trimmed); unset is the default;
//!   anything else is warned about once per name and read as the default.
//! - [`parse`]: a number or another `FromStr` value, with the same rule for a
//!   value that does not parse. Unset or blank is the default.
//! - [`var`]: a free-form value (an address, a list, a mode word).
//!
//! [`profile`] holds the adopted-configuration presets (`N42_PROFILE=x22`),
//! applied at process start before any knob is read.

use std::collections::HashSet;
use std::env::VarError;
use std::str::FromStr;
use std::sync::Mutex;

pub mod profile;

/// Names already warned about, so a knob read on a hot path (or by several
/// `OnceLock`s) logs its bad value once.
static WARNED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Whether `name` has not been warned about yet; records it.
fn first_warning(name: &str) -> bool {
    let mut warned = WARNED.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    warned.get_or_insert_with(HashSet::new).insert(name.to_owned())
}

fn warn_once(name: &str, value: &str, expected: &str, default: &dyn std::fmt::Debug) {
    if first_warning(name) {
        tracing::warn!(
            target: "n42::env",
            knob = name,
            value,
            expected,
            "unrecognised value for {name}; using the default {default:?}"
        );
    }
}

/// How a switch value reads: `Some(true)` for `1|true|on|yes`, `Some(false)`
/// for `0|false|off|no` and the empty string, `None` for anything else.
/// Case-insensitive, surrounding whitespace ignored.
pub fn parse_flag(value: &str) -> Option<bool> {
    let value = value.trim();
    if value.is_empty() {
        return Some(false);
    }
    const ON: [&str; 4] = ["1", "true", "on", "yes"];
    const OFF: [&str; 4] = ["0", "false", "off", "no"];
    if ON.iter().any(|word| value.eq_ignore_ascii_case(word)) {
        Some(true)
    } else if OFF.iter().any(|word| value.eq_ignore_ascii_case(word)) {
        Some(false)
    } else {
        None
    }
}

/// The switch `name`: unset reads `default`; see [`parse_flag`] for the
/// values. A value that is neither on nor off (or not Unicode) is warned
/// about once and reads `default`.
pub fn flag(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(raw)) => {
            warn_once(name, &raw.to_string_lossy(), "1|true|on|yes or 0|false|off|no", &default);
            default
        }
        Ok(value) => parse_flag(&value).unwrap_or_else(|| {
            warn_once(name, &value, "1|true|on|yes or 0|false|off|no", &default);
            default
        }),
    }
}

/// The value of `name` parsed as `T` (trimmed): unset or blank reads
/// `default`; a value that does not parse (or is not Unicode) is warned about
/// once and reads `default`.
pub fn parse<T: FromStr + std::fmt::Debug>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Err(VarError::NotPresent) => default,
        Err(VarError::NotUnicode(raw)) => {
            warn_once(name, &raw.to_string_lossy(), std::any::type_name::<T>(), &default);
            default
        }
        Ok(value) if value.trim().is_empty() => default,
        Ok(value) => value.trim().parse().unwrap_or_else(|_| {
            warn_once(name, &value, std::any::type_name::<T>(), &default);
            default
        }),
    }
}

/// The free-form value of `name`, as set (not trimmed). `None` when unset;
/// a value that is not Unicode is warned about once and reads as unset.
pub fn var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(raw)) => {
            warn_once(name, &raw.to_string_lossy(), "a Unicode string", &"unset");
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::{Mutex, MutexGuard};

    /// Serialises every test that touches the process environment.
    static ENV: Mutex<()> = Mutex::new(());

    pub(crate) fn lock() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn set(name: &str, value: impl AsRef<std::ffi::OsStr>) {
        // SAFETY: every test that reads or writes the environment holds
        // `ENV` (callers take `lock()` first), and these knob names are read
        // by nothing else in this test binary, so no other thread touches the
        // environment concurrently.
        unsafe { std::env::set_var(name, value) };
    }

    pub(crate) fn unset(name: &str) {
        // SAFETY: as for `set`.
        unsafe { std::env::remove_var(name) };
    }
}

#[cfg(test)]
mod tests {
    use super::test_env::{lock, set, unset};
    use super::*;

    #[test]
    fn parse_flag_reads_every_spelling() {
        for on in ["1", "true", "TRUE", "On", "yes", " YES ", "\ttrue\n"] {
            assert_eq!(parse_flag(on), Some(true), "{on:?}");
        }
        for off in ["0", "false", "False", "OFF", "no", " No ", "", "   "] {
            assert_eq!(parse_flag(off), Some(false), "{off:?}");
        }
        for garbage in ["2", "y", "enable", "1 1", "-1", "onn"] {
            assert_eq!(parse_flag(garbage), None, "{garbage:?}");
        }
    }

    #[test]
    fn flag_unset_reads_the_default() {
        let _guard = lock();
        unset("N42_ENV_TEST_FLAG_UNSET");
        assert!(!flag("N42_ENV_TEST_FLAG_UNSET", false));
        assert!(flag("N42_ENV_TEST_FLAG_UNSET", true));
    }

    #[test]
    fn flag_on_and_off_override_either_default() {
        let _guard = lock();
        let name = "N42_ENV_TEST_FLAG_SET";
        for (value, want) in [("1", true), ("yes", true), ("0", false), ("off", false), ("", false)] {
            set(name, value);
            assert_eq!(flag(name, false), want, "{value:?} with default off");
            assert_eq!(flag(name, true), want, "{value:?} with default on");
        }
        unset(name);
    }

    /// The behaviour change of this crate: `=0` on a former presence-only
    /// switch now turns it off.
    #[test]
    fn zero_disables_a_default_off_switch() {
        let _guard = lock();
        let name = "N42_ENV_TEST_FLAG_ZERO";
        set(name, "0");
        assert!(!flag(name, false));
        unset(name);
    }

    #[test]
    fn flag_garbage_reads_the_default_and_warns_once() {
        let _guard = lock();
        let name = "N42_ENV_TEST_FLAG_GARBAGE";
        set(name, "maybe");
        assert!(!flag(name, false));
        assert!(flag(name, true));
        // The two reads above recorded the name; a third reports it seen.
        assert!(!first_warning(name));
        unset(name);
    }

    #[cfg(unix)]
    #[test]
    fn flag_not_unicode_reads_the_default() {
        use std::os::unix::ffi::OsStrExt;
        let _guard = lock();
        let name = "N42_ENV_TEST_FLAG_BYTES";
        set(name, std::ffi::OsStr::from_bytes(&[0x66, 0xff]));
        assert!(flag(name, true));
        assert!(!flag(name, false));
        assert_eq!(var(name), None);
        assert_eq!(parse(name, 7u32), 7);
        unset(name);
    }

    #[test]
    fn parse_reads_numbers_and_falls_back() {
        let _guard = lock();
        let name = "N42_ENV_TEST_PARSE";
        unset(name);
        assert_eq!(parse(name, 16usize), 16);
        set(name, " 32 ");
        assert_eq!(parse(name, 16usize), 32);
        set(name, "");
        assert_eq!(parse(name, 16usize), 16);
        set(name, "lots");
        assert_eq!(parse(name, 16usize), 16);
        assert!(!first_warning(name), "the bad value was warned about");
        set(name, "-3");
        assert_eq!(parse(name, 2i64), -3);
        assert_eq!(parse(name, 2u64), 2);
        set(name, "0.5");
        assert_eq!(parse(name, 1.0f64), 0.5);
        unset(name);
    }

    #[test]
    fn var_returns_the_raw_value() {
        let _guard = lock();
        let name = "N42_ENV_TEST_VAR";
        unset(name);
        assert_eq!(var(name), None);
        set(name, " 127.0.0.1:9 ");
        assert_eq!(var(name).as_deref(), Some(" 127.0.0.1:9 "));
        set(name, "");
        assert_eq!(var(name).as_deref(), Some(""));
        unset(name);
    }

    #[test]
    fn first_warning_is_per_name() {
        assert!(first_warning("N42_ENV_TEST_WARN_A"));
        assert!(!first_warning("N42_ENV_TEST_WARN_A"));
        assert!(first_warning("N42_ENV_TEST_WARN_B"));
    }
}
