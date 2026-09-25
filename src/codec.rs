//! The field codecs the root's two signed documents share: the update ([`crate::roster`]) and `state`
//! ([`crate::state`]).
//!
//! Both are big-endian, length-prefixed and canonical: every list is strictly ascending by its own key, so
//! one document has one byte-string and a parser refuses any other order rather than re-sorting it. Each
//! reader here checks its bound before it allocates, so untrusted bytes are a clean [`FormatError`], never
//! a panic or a large allocation.

use core::fmt;
use core::str::FromStr as _;

use nauthy::{Link, RevocationId, VerifyKey};

use crate::contacts::DeviceLabel;

/// The most live devices one update lists.
pub const MAX_MEMBERS: usize = 4096;

/// The most unexpired revoked ids one document carries.
pub const MAX_REVOKED: usize = 16384;

/// The most revoked device keys one document carries.
pub const MAX_REVOKED_KEYS: usize = 4096;

/// The longest revocation id, in bytes.
pub const MAX_REVOCATION_ID: usize = 64;

/// The longest standing, in bytes of its bare link text.
pub const MAX_BADGE: usize = 1024;

/// The most ids one device carries: its live standings.
pub const MAX_IDS: usize = 4;

/// The framing can spell every bound it is built from, so every cast in the encoders is lossless.
const _: () = {
    assert!(
        DeviceLabel::MAX_LEN <= u16::MAX as usize,
        "a name fits its u16 length"
    );
    assert!(
        MAX_REVOCATION_ID <= u16::MAX as usize,
        "an id fits its u16 length"
    );
    assert!(
        MAX_BADGE <= u16::MAX as usize,
        "a standing fits its u16 length"
    );
    assert!(MAX_IDS <= u8::MAX as usize, "the ids fit their u8 count");
    assert!(
        MAX_MEMBERS + MAX_REVOKED_KEYS <= u32::MAX as usize,
        "the rows fit their u32 count"
    );
    assert!(
        MAX_REVOKED <= u32::MAX as usize,
        "the revoked ids fit their u32 count"
    );
};

/// One revocation id and the expiry of the standing it names. The id is an opaque signature, so its expiry
/// cannot be read off it: every rule that drops or caps ids by age reads `expires`.
#[derive(Clone, PartialEq, Eq)]
pub struct Id {
    /// The expiry of the standing this id names, in unix seconds.
    pub expires: u64,
    /// The id itself, at most [`MAX_REVOCATION_ID`] bytes.
    pub id: RevocationId,
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Id")
            .field("expires", &self.expires)
            .field("id", &self.id.to_hex())
            .finish()
    }
}

/// Why a document could not be built or parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FormatError {
    /// The payload did not open with this document's magic and version.
    #[error("not this document (bad magic or version)")]
    BadMagic,
    /// The payload ended before a field was complete, or carried trailing bytes.
    #[error("the document is truncated or malformed")]
    Truncated,
    /// A label was not a device name.
    #[error("invalid device name: {0}")]
    BadLabel(&'static str),
    /// A standing was not a bare link.
    #[error("a standing is not a link")]
    BadStanding,
    /// A flag byte was neither 0 nor 1.
    #[error("a flag is neither 0 nor 1")]
    BadFlag,
    /// A device key is not a key anyone can hold.
    #[error("a device key is not a usable key: {0}")]
    BadKey(nauthy::KeyError),
    /// Two devices share one key.
    #[error("the document lists device {0} twice")]
    DuplicateNode(VerifyKey),
    /// Two devices that are not revoked share one name.
    #[error("the document lists the name {0} twice")]
    DuplicateLabel(DeviceLabel),
    /// A device's row is revoked but its key is not a revoked key, or its row is live and its key is.
    #[error("device {0} is revoked in one list and not the other")]
    RevokedMismatch(VerifyKey),
    /// A list was not strictly ascending, or held one entry twice.
    #[error("the document's entries are not in canonical order")]
    NonCanonicalOrder,
    /// A list or a field was over its bound.
    #[error("the document's {0} is over its bound")]
    TooLarge(&'static str),
}

/// Sort `items` by `key` and refuse a repeat, so a built document encodes one way.
pub(crate) fn canonicalize<T, K: Ord>(
    items: &mut [T],
    key: impl Fn(&T) -> K,
) -> Result<(), FormatError> {
    items.sort_by_key(|item| key(item));
    if items.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        return Err(FormatError::NonCanonicalOrder);
    }
    Ok(())
}

/// Check a device's ids and standing against their bounds, and sort its ids.
pub(crate) fn check_device(ids: &mut [Id], standing: &Link) -> Result<(), FormatError> {
    bound(ids.len(), MAX_IDS, "ids")?;
    check_ids(ids)?;
    bound(standing.as_str().len(), MAX_BADGE, "standing")
}

/// Check each id against [`MAX_REVOCATION_ID`], and sort them.
pub(crate) fn check_ids(ids: &mut [Id]) -> Result<(), FormatError> {
    for id in ids.iter() {
        bound(id.id.as_bytes().len(), MAX_REVOCATION_ID, "revocation id")?;
    }
    canonicalize(ids, |id| id.id.as_bytes().to_vec())
}

/// Refuse two devices under one name.
pub(crate) fn unique_labels<'a>(
    labels: impl Iterator<Item = &'a DeviceLabel>,
) -> Result<(), FormatError> {
    let mut labels: Vec<&DeviceLabel> = labels.collect();
    labels.sort();
    match labels.windows(2).find(|pair| pair[0] == pair[1]) {
        Some(pair) => Err(FormatError::DuplicateLabel(pair[0].clone())),
        None => Ok(()),
    }
}

/// Refuse `len` over `max`, naming the field.
pub(crate) fn bound(len: usize, max: usize, field: &'static str) -> Result<(), FormatError> {
    if len > max {
        return Err(FormatError::TooLarge(field));
    }
    Ok(())
}

/// The encoder's side: fields appended to a buffer. Every length was bounded when the document was built,
/// so no cast here truncates.
pub(crate) trait Put {
    fn put_u8(&mut self, value: u8);
    fn put_u16(&mut self, value: usize);
    fn put_u32(&mut self, value: usize);
    fn put_u64(&mut self, value: u64);
    fn put_bytes16(&mut self, bytes: &[u8]);
    fn put_id(&mut self, id: &Id);
    fn put_ids32(&mut self, ids: &[Id]);
    fn put_keys32(&mut self, keys: &[VerifyKey]);
}

impl Put for Vec<u8> {
    fn put_u8(&mut self, value: u8) {
        self.push(value);
    }

    fn put_u16(&mut self, value: usize) {
        self.extend_from_slice(&(value as u16).to_be_bytes());
    }

    fn put_u32(&mut self, value: usize) {
        self.extend_from_slice(&(value as u32).to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    fn put_bytes16(&mut self, bytes: &[u8]) {
        self.put_u16(bytes.len());
        self.extend_from_slice(bytes);
    }

    fn put_id(&mut self, id: &Id) {
        self.put_u64(id.expires);
        self.put_bytes16(id.id.as_bytes());
    }

    fn put_ids32(&mut self, ids: &[Id]) {
        self.put_u32(ids.len());
        for id in ids {
            self.put_id(id);
        }
    }

    fn put_keys32(&mut self, keys: &[VerifyKey]) {
        self.put_u32(keys.len());
        for key in keys {
            self.extend_from_slice(key.bytes());
        }
    }
}

/// The parser's side: a cursor over untrusted bytes.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    cur: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `bytes`, past `magic` and `version`. The magic is compared by its own
    /// length, so no magic is padded to a width.
    pub(crate) fn open(bytes: &'a [u8], magic: &[u8], version: u8) -> Result<Self, FormatError> {
        let mut reader = Self { bytes, cur: 0 };
        let head = reader
            .take(magic.len())
            .map_err(|_| FormatError::BadMagic)?;
        let found = reader.u8().map_err(|_| FormatError::BadMagic)?;
        if head != magic || found != version {
            return Err(FormatError::BadMagic);
        }
        Ok(reader)
    }

    /// Refuse trailing bytes.
    pub(crate) fn finish(self) -> Result<(), FormatError> {
        if self.cur != self.bytes.len() {
            return Err(FormatError::Truncated);
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        let end = self.cur.checked_add(n).ok_or(FormatError::Truncated)?;
        let slice = self
            .bytes
            .get(self.cur..end)
            .ok_or(FormatError::Truncated)?;
        self.cur = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        self.take(N)?.try_into().map_err(|_| FormatError::Truncated)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<usize, FormatError> {
        Ok(usize::from(u16::from_be_bytes(self.array()?)))
    }

    pub(crate) fn u32(&mut self) -> Result<usize, FormatError> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| FormatError::Truncated)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A flag byte: 0 or 1, nothing else, so one document has one byte-string.
    pub(crate) fn flag(&mut self) -> Result<bool, FormatError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FormatError::BadFlag),
        }
    }

    /// A count, refused over `max` before anything is allocated for it.
    pub(crate) fn count32(
        &mut self,
        max: usize,
        field: &'static str,
    ) -> Result<usize, FormatError> {
        let count = self.u32()?;
        bound(count, max, field)?;
        Ok(count)
    }

    pub(crate) fn key(&mut self) -> Result<VerifyKey, FormatError> {
        VerifyKey::try_new(self.array()?).map_err(FormatError::BadKey)
    }

    /// A `u16`-prefixed device name, read as stored: a capital refuses rather than folding, so two
    /// byte-strings never decode to one document.
    pub(crate) fn label(&mut self) -> Result<DeviceLabel, FormatError> {
        let len = self.u16()?;
        let text = core::str::from_utf8(self.take(len)?)
            .map_err(|_| FormatError::BadLabel("not valid UTF-8"))?;
        DeviceLabel::stored(text).map_err(|_| FormatError::BadLabel("not a device name"))
    }

    /// A `u16`-prefixed standing: bare link text, at most [`MAX_BADGE`] bytes.
    pub(crate) fn standing(&mut self) -> Result<Link, FormatError> {
        let len = self.u16()?;
        bound(len, MAX_BADGE, "standing")?;
        let text = core::str::from_utf8(self.take(len)?).map_err(|_| FormatError::BadStanding)?;
        Link::from_str(text).map_err(|_| FormatError::BadStanding)
    }

    fn id(&mut self) -> Result<Id, FormatError> {
        let expires = self.u64()?;
        let len = self.u16()?;
        bound(len, MAX_REVOCATION_ID, "revocation id")?;
        Ok(Id {
            expires,
            id: RevocationId::from_bytes(self.take(len)?),
        })
    }

    /// A device's `u8`-counted ids, at most [`MAX_IDS`], strictly ascending.
    pub(crate) fn device_ids(&mut self) -> Result<Vec<Id>, FormatError> {
        let count = usize::from(self.u8()?);
        bound(count, MAX_IDS, "ids")?;
        self.ids(count)
    }

    /// The `u32`-counted revoked ids, at most [`MAX_REVOKED`], strictly ascending.
    pub(crate) fn revoked(&mut self) -> Result<Vec<Id>, FormatError> {
        let count = self.count32(MAX_REVOKED, "revoked ids")?;
        self.ids(count)
    }

    fn ids(&mut self, count: usize) -> Result<Vec<Id>, FormatError> {
        let mut ids: Vec<Id> = Vec::with_capacity(count);
        for _ in 0..count {
            let id = self.id()?;
            if ids
                .last()
                .is_some_and(|previous| id.id.as_bytes() <= previous.id.as_bytes())
            {
                return Err(FormatError::NonCanonicalOrder);
            }
            ids.push(id);
        }
        Ok(ids)
    }

    /// The `u32`-counted revoked keys, at most [`MAX_REVOKED_KEYS`], strictly ascending.
    pub(crate) fn revoked_keys(&mut self) -> Result<Vec<VerifyKey>, FormatError> {
        let count = self.count32(MAX_REVOKED_KEYS, "revoked keys")?;
        let mut keys: Vec<VerifyKey> = Vec::with_capacity(count);
        for _ in 0..count {
            let key = self.key()?;
            if keys
                .last()
                .is_some_and(|previous| key.bytes() <= previous.bytes())
            {
                return Err(FormatError::NonCanonicalOrder);
            }
            keys.push(key);
        }
        Ok(keys)
    }
}
