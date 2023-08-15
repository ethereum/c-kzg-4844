//! Serde serialization and deserialization for the basic types in this crate.
//!
//! The implementations are modified from the `[T; N]` implementations in
//! `serde` itself.
//!
//! Serialize impls from `serde`:
//! <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/ser/impls.rs>
//!
//! Deserialize impls from `serde`:
//! <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs>
use crate::{Blob, Bytes48, BYTES_PER_BLOB};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize,
    __private::de::InPlaceSeed,
};
use std::{fmt, marker::PhantomData};

/// Copied from serde:
/// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1100-L1111>
struct ArrayVisitor<A> {
    marker: PhantomData<A>,
}

struct ArrayInPlaceVisitor<'a, A: 'a>(&'a mut A);

impl<A> ArrayVisitor<A> {
    fn new() -> Self {
        ArrayVisitor {
            marker: PhantomData,
        }
    }
}

// === Blob ===

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/ser/impls.rs#L143-L158>
impl Serialize for Blob {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(BYTES_PER_BLOB)?;
        for e in self.as_ref() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

// modified slightly from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1142-L1164>
impl<'de> Visitor<'de> for ArrayVisitor<[u8; BYTES_PER_BLOB]> {
    type Value = [u8; BYTES_PER_BLOB];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(format!("an array of length {}", BYTES_PER_BLOB).as_str())
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut arr = [0u8; BYTES_PER_BLOB];
        for (i, elem) in arr.iter_mut().enumerate() {
            match seq.next_element::<u8>()? {
                Some(val) => *elem = val,
                None => return Err(serde::de::Error::invalid_length(i, &self)),
            }
        }
        Ok(arr)
    }
}

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1166-L1193>
impl<'de> Visitor<'de> for ArrayInPlaceVisitor<'_, [u8; BYTES_PER_BLOB]> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(format!("an array of length {}", BYTES_PER_BLOB).as_str())
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut fail_idx = None;
        for (idx, dest) in self.0[..].iter_mut().enumerate() {
            if seq.next_element_seed(InPlaceSeed(dest))?.is_none() {
                fail_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = fail_idx {
            return Err(serde::de::Error::invalid_length(idx, &self));
        }

        Ok(())
    }
}

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1195-L1212>
impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer
            .deserialize_tuple(BYTES_PER_BLOB, ArrayVisitor::<[u8; BYTES_PER_BLOB]>::new())?;
        Ok(Blob { bytes })
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(
            BYTES_PER_BLOB,
            ArrayInPlaceVisitor::<[u8; BYTES_PER_BLOB]>(place),
        )
    }
}

// === Bytes48 ===

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/ser/impls.rs#L143-L158>
impl Serialize for Bytes48 {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(48)?;
        for e in self.as_ref() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

// modified slightly from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1142-L1164>
impl<'de> Visitor<'de> for ArrayVisitor<[u8; 48]> {
    type Value = [u8; 48];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(format!("an array of length {}", 48).as_str())
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut arr = [0u8; 48];
        for (i, elem) in arr.iter_mut().enumerate() {
            match seq.next_element::<u8>()? {
                Some(val) => *elem = val,
                None => return Err(serde::de::Error::invalid_length(i, &self)),
            }
        }
        Ok(arr)
    }
}

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1166-L1193>
impl<'de> Visitor<'de> for ArrayInPlaceVisitor<'_, [u8; 48]> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an array of length 48")
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut fail_idx = None;
        for (idx, dest) in self.0[..].iter_mut().enumerate() {
            if seq.next_element_seed(InPlaceSeed(dest))?.is_none() {
                fail_idx = Some(idx);
                break;
            }
        }

        if let Some(idx) = fail_idx {
            return Err(serde::de::Error::invalid_length(idx, &self));
        }

        Ok(())
    }
}

// copied from serde:
// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1195-L1212>
impl<'de> Deserialize<'de> for Bytes48 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_tuple(48, ArrayVisitor::<[u8; 48]>::new())?;
        Ok(Bytes48 { bytes })
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(48, ArrayInPlaceVisitor::<[u8; 48]>(place))
    }
}
