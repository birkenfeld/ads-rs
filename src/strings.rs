//! Utilities to generate and work with fixed-length string types.
//!
//! The macros [`make_string_type`] and [`make_wstring_type`] are exported from
//! the crate root.

// TODO: replace with const generics once we bump MSRV.

/// Create a new type representing a `STRING(len)` in the PLC, which can be used
/// with Device::read/write_value or Symbol::read/write_value.
///
/// For example:
/// ```
/// ads::make_string_type!(String256, 256);
/// ```
///
/// `String80` is already predefined in `ads::strings`.
#[macro_export]
macro_rules! make_string_type {
    ($name:ident, $len:expr) => {
        /// Represents a fixed-length byte string.
        ///
        /// This type can be created from a `&str` or `&[u8]` if their byte
        /// length does not exceed the fixed length.
        ///
        /// It can be freely converted from and to a `[u8; N]` array, and
        /// to a `Vec<u8>` where it will be cut at the first null byte.
        ///
        /// It can be converted to a Rust `String` if it is UTF8 encoded.
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct $name([u8; $len], u8);  // one extra NULL byte

        impl $name {
            fn new() -> Self {
                Self([0; $len], 0)
            }
        }

        impl std::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        // conversion with [u8; N]

        impl std::convert::From<[u8; $len]> for $name {
            fn from(arr: [u8; $len]) -> Self {
                Self(arr, 0)
            }
        }

        impl std::convert::From<$name> for [u8; $len] {
            fn from(bstr: $name) -> Self {
                bstr.0
            }
        }

        // conversion with bytes

        impl std::convert::TryFrom<&'_ [u8]> for $name {
            type Error = ();
            fn try_from(arr: &[u8]) -> std::result::Result<Self, ()> {
                if arr.len() > $len {
                    return Err(());
                }
                let mut bstr = Self::new();
                bstr.0[..arr.len()].copy_from_slice(arr);
                Ok(bstr)
            }
        }

        impl std::convert::From<$name> for std::vec::Vec<u8> {
            fn from(bstr: $name) -> Self {
                let nullpos = bstr.0.iter().position(|&b| b == 0).unwrap_or(bstr.0.len());
                bstr.0[..nullpos].to_vec()
            }
        }

        // conversion with strings

        impl std::convert::TryFrom<&'_ str> for $name {
            type Error = ();
            fn try_from(s: &str) -> std::result::Result<Self, ()> {
                Self::try_from(s.as_bytes())
            }
        }

        impl std::convert::TryFrom<$name> for std::string::String {
            type Error = std::str::Utf8Error;
            fn try_from(bytes: $name) -> std::result::Result<Self, Self::Error> {
                let nullpos = bytes.0.iter().position(|&b| b == 0).unwrap_or(bytes.0.len());
                std::str::from_utf8(&bytes.0[..nullpos]).map(Into::into)
            }
        }

        // zerocopy implementations

        unsafe impl zerocopy::AsBytes for $name {
            fn only_derive_is_allowed_to_implement_this_trait() { }
        }

        unsafe impl zerocopy::FromBytes for $name {
            fn only_derive_is_allowed_to_implement_this_trait() { }
        }
    };
}

/// Create a new type representing a `WSTRING(len)` in the PLC, which can be used
/// with Device::read/write_value or Symbol::read/write_value.
///
/// For example:
/// ```
/// ads::make_wstring_type!(WString256, 256);
/// ```
///
/// `WString80` is already predefined in `ads::strings`.
#[macro_export]
macro_rules! make_wstring_type {
    ($name:ident, $len:expr) => {
        /// Represents a fixed-length wide string.
        ///
        /// This type can be created from a `&[u16]` if its length does not
        /// exceed the fixed length.  It can be created from a `&str` if its
        /// length, encoded in UTF16, does not exceed the fixed length.
        ///
        /// It can be freely converted from and to a `[u16; N]` array, and
        /// to a `Vec<u16>` where it will be cut at the first null.
        ///
        /// It can be converted to a Rust `String` if it is properly UTF16
        /// encoded.
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct $name([u16; $len], u16);  // one extra NULL byte

        impl $name {
            fn new() -> Self {
                Self([0; $len], 0)
            }
        }

        impl std::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        // conversion with [u16; N]

        impl std::convert::From<[u16; $len]> for $name {
            fn from(arr: [u16; $len]) -> Self {
                Self(arr, 0)
            }
        }

        impl std::convert::From<$name> for [u16; $len] {
            fn from(wstr: $name) -> Self {
                wstr.0
            }
        }

        // conversion with [u16]

        impl std::convert::TryFrom<&'_ [u16]> for $name {
            type Error = ();
            fn try_from(arr: &[u16]) -> std::result::Result<Self, ()> {
                if arr.len() > $len {
                    return Err(());
                }
                let mut wstr = Self::new();
                wstr.0[..arr.len()].copy_from_slice(arr);
                Ok(wstr)
            }
        }

        impl std::convert::From<$name> for std::vec::Vec<u16> {
            fn from(wstr: $name) -> Self {
                let nullpos = wstr.0.iter().position(|&b| b == 0).unwrap_or(wstr.0.len());
                wstr.0[..nullpos].to_vec()
            }
        }

        // conversion with strings

        impl std::convert::TryFrom<&'_ str> for $name {
            type Error = ();
            fn try_from(s: &str) -> std::result::Result<Self, ()> {
                let mut wstr = Self::new();
                for (i, unit) in s.encode_utf16().enumerate() {
                    if i >= wstr.0.len() {
                        return Err(());
                    }
                    wstr.0[i] = unit;
                }
                Ok(wstr)
            }
        }

        impl std::convert::TryFrom<$name> for std::string::String {
            type Error = std::char::DecodeUtf16Error;
            fn try_from(wstr: $name) -> std::result::Result<Self, Self::Error> {
                std::char::decode_utf16(wstr.0.iter().cloned().take_while(|&b| b != 0)).collect()
            }
        }

        // zerocopy implementations

        unsafe impl zerocopy::AsBytes for $name {
            fn only_derive_is_allowed_to_implement_this_trait() { }
        }

        unsafe impl zerocopy::FromBytes for $name {
            fn only_derive_is_allowed_to_implement_this_trait() { }
        }
    };
}

make_string_type!(String80, 80);
make_wstring_type!(WString80, 80);
