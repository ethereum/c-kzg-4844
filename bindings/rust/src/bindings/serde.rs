///! Serde serialization and deserialization for the basic types in this crate.
///!
///! The implementations are modified from the `[T; N]` implementations in
///! `serde` itself.

/// Copied from serde:
/// <https://github.com/serde-rs/serde/blob/7b548db91ed7da81a5c0ddbd6f6f21238aacfebe/serde/src/de/impls.rs#L1100>
struct ArrayVisitor<A> {
    marker: PhantomData<A>,
}

impl<A> ArrayVisitor<A> {
    fn new() -> Self {
        ArrayVisitor {
            marker: PhantomData,
        }
    }
}

// === BlobSerde ===

impl Serialize for BlobSerde {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(BYTES_PER_BLOB)?;
        for e in self.0.as_ref() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl <'de> Visitor<'de> for ArrayVisitor<[u8; BYTES_PER_BLOB]>
{
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

impl<'de> Deserialize<'de> for BlobSerde {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = deserializer.deserialize_tuple(BYTES_PER_BLOB, ArrayVisitor::<[u8; BYTES_PER_BLOB]>::new())?;
        Ok(BlobSerde(val.into()))
    }
}

// === Bytes48Serde ===

impl Serialize for Bytes48Serde {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(48)?;
        for e in self.0.as_ref() {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

impl <'de> Visitor<'de> for ArrayVisitor<[u8; 48]>
{
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

impl<'de> Deserialize<'de> for Bytes48Serde {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = deserializer.deserialize_tuple(48, ArrayVisitor::<[u8; 48]>::new())?;
        Ok(Bytes48Serde(val.into()))
    }
}
