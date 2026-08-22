//! Minimal, hand-rolled BER codec for LDAP **simple bind** and **search**
//! (RFC 4511).
//!
//! Bind PDUs stay capped at [`MAX_LDAP_MESSAGE`] (64 KiB). Search result
//! PDUs use [`MAX_SEARCH_LDAP_MESSAGE`] (256 KiB). A `memberOf;range=`
//! attribute or a key-list overflow is incomplete (case C), never a
//! silent subset.
//!
//! Robustness contract: the decoder is **fail-closed**. Any malformed,
//! truncated, indefinite-length or oversized input yields an `io::Error`.

use std::io::{self, Read, Write};

/// LDAP `resultCode` for a successful bind.
pub const LDAP_SUCCESS: i64 = 0;
/// LDAP `resultCode` for rejected credentials.
pub const LDAP_INVALID_CREDENTIALS: i64 = 49;

/// Hard upper bound on a single **bind** LDAP message we will buffer.
pub const MAX_LDAP_MESSAGE: usize = 64 * 1024;
/// Hard upper bound on a single **search** result PDU (one user entry with
/// a large `memberOf` must fit). Overflow is case C, not a silent subset.
pub const MAX_SEARCH_LDAP_MESSAGE: usize = 256 * 1024;
/// Maximum directory keys collected per bind-and-search.
pub const MAX_GROUP_KEYS: usize = 1024;
/// Combined key payload cap (under the 256 KiB IPC envelope).
pub const MAX_GROUP_KEYS_BYTES: usize = 192 * 1024;
/// Maximum bytes of a single collected key.
pub const MAX_GROUP_KEY_BYTES: usize = 512;

/// LDAP `resultCode` for no such object.
pub const LDAP_NO_SUCH_OBJECT: i64 = 32;
/// LDAP `resultCode` for insufficient access rights.
pub const LDAP_INSUFFICIENT_ACCESS: i64 = 50;

// BER/DER tags used by the simple-bind exchange.
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_SEQUENCE: u8 = 0x30;
/// `[APPLICATION 0]` constructed: BindRequest.
const TAG_BIND_REQUEST: u8 = 0x60;
/// `[APPLICATION 1]` constructed: BindResponse.
const TAG_BIND_RESPONSE: u8 = 0x61;
/// `[0]` primitive (context-specific): simple authentication in BindRequest.
const TAG_SIMPLE_AUTH: u8 = 0x80;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_SET: u8 = 0x31;
/// `[APPLICATION 3]` constructed: SearchRequest.
const TAG_SEARCH_REQUEST: u8 = 0x63;
/// `[APPLICATION 4]` constructed: SearchResultEntry.
const TAG_SEARCH_RESULT_ENTRY: u8 = 0x64;
/// `[APPLICATION 5]` constructed: SearchResultDone.
const TAG_SEARCH_RESULT_DONE: u8 = 0x65;
/// `[APPLICATION 19]` constructed: SearchResultReference (ignored, never followed).
const TAG_SEARCH_RESULT_REFERENCE: u8 = 0x73;
/// Filter `equalityMatch` `[3]` constructed.
const TAG_FILTER_EQUALITY: u8 = 0xa3;
/// Filter `present` `[7]` primitive.
const TAG_FILTER_PRESENT: u8 = 0x87;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Encode a BER definite length prefix into `out`.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    // `bytes.len()` is <= 8 for any usize, so the 0x80 | count form is safe.
    out.push(0x80 | (bytes.len() as u8));
    out.extend_from_slice(&bytes);
}

/// Encode a single tag-length-value triple.
fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    encode_length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Encode a signed INTEGER in its minimal two's-complement big-endian form.
fn encode_integer(value: i64) -> Vec<u8> {
    let be = value.to_be_bytes();
    // Strip redundant leading sign-extension bytes while preserving the sign
    // bit of the first retained byte.
    let mut start = 0usize;
    while start < be.len() - 1 {
        let b = be[start];
        let next = be[start + 1];
        let is_pos_pad = b == 0x00 && (next & 0x80) == 0;
        let is_neg_pad = b == 0xff && (next & 0x80) != 0;
        if is_pos_pad || is_neg_pad {
            start += 1;
        } else {
            break;
        }
    }
    encode_tlv(TAG_INTEGER, &be[start..])
}

/// Encode an `LDAPMessage` carrying a simple `BindRequest`.
///
/// `message_id` is the LDAP message id (any positive value; the directory
/// echoes it). `dn` is the bind DN, `password` the simple-auth secret bytes.
#[must_use]
pub fn encode_bind_request(message_id: i64, dn: &str, password: &[u8]) -> Vec<u8> {
    let mut bind = Vec::new();
    bind.extend_from_slice(&encode_integer(3)); // version = 3
    bind.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, dn.as_bytes())); // name
    bind.extend_from_slice(&encode_tlv(TAG_SIMPLE_AUTH, password)); // [0] simple
    let bind_request = encode_tlv(TAG_BIND_REQUEST, &bind);

    let mut msg = Vec::new();
    msg.extend_from_slice(&encode_integer(message_id));
    msg.extend_from_slice(&bind_request);
    encode_tlv(TAG_SEQUENCE, &msg)
}

/// Decode a BER definite length from the front of `buf`.
///
/// Returns `(length, header_bytes_consumed)`. Rejects the indefinite form
/// (`0x80`), long forms wider than 4 bytes, and any length exceeding `max`.
fn decode_length_capped(buf: &[u8], max: usize) -> io::Result<(usize, usize)> {
    let first = *buf.first().ok_or_else(|| invalid("missing length octet"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    if first == 0x80 {
        return Err(invalid("indefinite BER length is not allowed"));
    }
    let num = (first & 0x7f) as usize;
    if num > 4 || buf.len() < 1 + num {
        return Err(invalid("invalid long-form BER length"));
    }
    let mut len = 0usize;
    for &b in &buf[1..1 + num] {
        len = (len << 8) | b as usize;
    }
    if len > max {
        return Err(invalid("LDAP message length exceeds maximum"));
    }
    Ok((len, 1 + num))
}

fn decode_length(buf: &[u8]) -> io::Result<(usize, usize)> {
    decode_length_capped(buf, MAX_LDAP_MESSAGE)
}

/// Read one TLV from `buf`, returning `(tag, content, rest)`.
fn read_tlv(buf: &[u8]) -> io::Result<(u8, &[u8], &[u8])> {
    let tag = *buf.first().ok_or_else(|| invalid("truncated TLV tag"))?;
    let (len, header) = decode_length(&buf[1..])?;
    let start = 1 + header;
    let end = start
        .checked_add(len)
        .ok_or_else(|| invalid("TLV length overflow"))?;
    if end > buf.len() {
        return Err(invalid("truncated TLV content"));
    }
    Ok((tag, &buf[start..end], &buf[end..]))
}

/// Decode a signed INTEGER/ENUMERATED value (1..=8 bytes).
fn decode_integer(bytes: &[u8]) -> io::Result<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(invalid("invalid INTEGER length"));
    }
    let negative = (bytes[0] & 0x80) != 0;
    let mut val: i64 = if negative { -1 } else { 0 };
    for &b in bytes {
        val = (val << 8) | (b as i64 & 0xff);
    }
    Ok(val)
}

/// Parse a full `LDAPMessage` (including its outer SEQUENCE tag) carrying a
/// `BindResponse`, returning the LDAP `resultCode`.
///
/// Fail-closed: a wrong outer tag, a non-BindResponse protocolOp, a missing
/// resultCode, or any truncation yields an `io::Error`.
pub fn parse_bind_response(message: &[u8]) -> io::Result<i64> {
    let (tag, content, _rest) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    // messageID INTEGER (value ignored: we issue one bind at a time).
    let (id_tag, _id, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    // protocolOp = BindResponse [APPLICATION 1].
    let (br_tag, br_content, _) = read_tlv(rest)?;
    if br_tag != TAG_BIND_RESPONSE {
        return Err(invalid("expected BindResponse protocolOp"));
    }
    // resultCode ENUMERATED is the first field of BindResponse.
    let (rc_tag, rc_bytes, _) = read_tlv(br_content)?;
    if rc_tag != TAG_ENUMERATED {
        return Err(invalid("expected resultCode ENUMERATED"));
    }
    decode_integer(rc_bytes)
}

/// Read exactly one `LDAPMessage` off `stream`, returning the full encoding
/// (outer tag + length + content). Bounds the buffered size to
/// [`MAX_LDAP_MESSAGE`].
pub fn read_ldap_message<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    read_ldap_message_max(stream, MAX_LDAP_MESSAGE)
}

/// Read one `LDAPMessage` with a caller-chosen size cap (search PDUs).
pub fn read_ldap_message_max<S: Read>(stream: &mut S, max: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    let tag = header[0];
    let len_first = header[1];

    let mut full = vec![tag, len_first];
    let content_len = if len_first < 0x80 {
        len_first as usize
    } else if len_first == 0x80 {
        return Err(invalid("indefinite BER length is not allowed"));
    } else {
        let num = (len_first & 0x7f) as usize;
        if num > 4 {
            return Err(invalid("long-form BER length too wide"));
        }
        let mut num_bytes = vec![0u8; num];
        stream.read_exact(&mut num_bytes)?;
        full.extend_from_slice(&num_bytes);
        let mut len = 0usize;
        for &b in &num_bytes {
            len = (len << 8) | b as usize;
        }
        len
    };
    if content_len > max {
        return Err(invalid("LDAP message length exceeds maximum"));
    }
    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content)?;
    full.extend_from_slice(&content);
    Ok(full)
}

/// Perform a synchronous LDAP simple bind over an established (typically
/// TLS-wrapped) stream: write the `BindRequest`, read the `BindResponse`, and
/// return the LDAP `resultCode`.
pub fn simple_bind_on_stream<S: Read + Write>(
    stream: &mut S,
    dn: &str,
    password: &[u8],
) -> io::Result<i64> {
    let request = encode_bind_request(1, dn, password);
    stream.write_all(&request)?;
    stream.flush()?;
    let response = read_ldap_message(stream)?;
    parse_bind_response(&response)
}

/// Parse an `LDAPMessage` carrying a simple `BindRequest`, returning
/// `(messageID, bind DN, simple-auth password bytes)`.
///
/// This is the directory-side counterpart of [`encode_bind_request`], used by
/// the in-process LDAPS test server. Fail-closed on any structural deviation
/// (wrong tags, non-simple authentication, truncation).
pub fn parse_bind_request(message: &[u8]) -> io::Result<(i64, String, Vec<u8>)> {
    let (tag, content, _rest) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    let (id_tag, id_bytes, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    let message_id = decode_integer(id_bytes)?;

    let (br_tag, br_content, _) = read_tlv(rest)?;
    if br_tag != TAG_BIND_REQUEST {
        return Err(invalid("expected BindRequest protocolOp"));
    }
    // version INTEGER.
    let (v_tag, _v, after_v) = read_tlv(br_content)?;
    if v_tag != TAG_INTEGER {
        return Err(invalid("expected version INTEGER"));
    }
    // name OCTET STRING (the bind DN).
    let (n_tag, dn_bytes, after_n) = read_tlv(after_v)?;
    if n_tag != TAG_OCTET_STRING {
        return Err(invalid("expected name OCTET STRING"));
    }
    let dn =
        String::from_utf8(dn_bytes.to_vec()).map_err(|_| invalid("bind DN is not valid UTF-8"))?;
    // authentication [0] simple.
    let (a_tag, password, _) = read_tlv(after_n)?;
    if a_tag != TAG_SIMPLE_AUTH {
        return Err(invalid("expected simple authentication ([0])"));
    }
    Ok((message_id, dn, password.to_vec()))
}

/// Encode a minimal `BindResponse` `LDAPMessage` (empty matchedDN and
/// diagnosticMessage, as directories send on a bare accept/reject). Used by
/// the in-process LDAPS test server.
#[must_use]
pub fn encode_bind_response(message_id: i64, result_code: i64) -> Vec<u8> {
    let mut br = Vec::new();
    // resultCode ENUMERATED: reuse the INTEGER value bytes (same content form),
    // re-tagged as ENUMERATED.
    let rc_int = encode_integer(result_code);
    // rc_int = [0x02, len, value...]; rewrap the value under ENUMERATED.
    let rc_value = &rc_int[2..];
    br.extend_from_slice(&encode_tlv(TAG_ENUMERATED, rc_value));
    br.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, b"")); // matchedDN
    br.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, b"")); // diagnosticMessage
    let bind_response = encode_tlv(TAG_BIND_RESPONSE, &br);

    let mut msg = Vec::new();
    msg.extend_from_slice(&encode_integer(message_id));
    msg.extend_from_slice(&bind_response);
    encode_tlv(TAG_SEQUENCE, &msg)
}

/// Filter used in a SearchRequest.
#[derive(Debug, Clone)]
pub enum SearchFilter {
    /// `(attr=*)`
    Present(String),
    /// `(attr=value)` -- `value` is already RFC 4515-safe assertion bytes.
    Equality { attr: String, value: String },
}

/// Encode an `LDAPMessage` carrying a SearchRequest.
#[must_use]
pub fn encode_search_request(
    message_id: i64,
    base: &str,
    subtree: bool,
    filter: &SearchFilter,
    attributes: &[&str],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, base.as_bytes()));
    let scope = if subtree { 2 } else { 0 };
    body.extend_from_slice(&encode_tlv(TAG_ENUMERATED, &[scope]));
    body.extend_from_slice(&encode_tlv(TAG_ENUMERATED, &[0])); // neverDerefAliases
    body.extend_from_slice(&encode_integer(0)); // sizeLimit
    body.extend_from_slice(&encode_integer(0)); // timeLimit
    body.extend_from_slice(&encode_tlv(TAG_BOOLEAN, &[0x00])); // typesOnly
    match filter {
        SearchFilter::Present(attr) => {
            body.extend_from_slice(&encode_tlv(TAG_FILTER_PRESENT, attr.as_bytes()));
        }
        SearchFilter::Equality { attr, value } => {
            let mut ava = Vec::new();
            ava.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, attr.as_bytes()));
            ava.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, value.as_bytes()));
            body.extend_from_slice(&encode_tlv(TAG_FILTER_EQUALITY, &ava));
        }
    }
    let mut attrs = Vec::new();
    for a in attributes {
        attrs.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, a.as_bytes()));
    }
    body.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &attrs));
    let search = encode_tlv(TAG_SEARCH_REQUEST, &body);

    let mut msg = Vec::new();
    msg.extend_from_slice(&encode_integer(message_id));
    msg.extend_from_slice(&search);
    encode_tlv(TAG_SEQUENCE, &msg)
}

/// One attribute of a SearchResultEntry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialAttribute {
    pub type_: String,
    pub values: Vec<String>,
}

/// Parsed SearchResultEntry (objectName + attributes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchEntry {
    pub object_name: String,
    pub attributes: Vec<PartialAttribute>,
}

impl SearchEntry {
    /// Whether any attribute type carries `;range=` (AD truncation).
    #[must_use]
    pub fn has_range_attribute(&self) -> bool {
        self.attributes
            .iter()
            .any(|a| a.type_.to_ascii_lowercase().contains(";range="))
    }

    /// Values of `attr` (case-insensitive type match, ignoring options).
    #[must_use]
    pub fn values_of(&self, attr: &str) -> Vec<String> {
        let want = attr.to_ascii_lowercase();
        self.attributes
            .iter()
            .filter(|a| {
                a.type_
                    .split(';')
                    .next()
                    .unwrap_or(&a.type_)
                    .eq_ignore_ascii_case(&want)
            })
            .flat_map(|a| a.values.iter().cloned())
            .collect()
    }
}

/// Decode a SearchResultEntry protocolOp.
pub fn parse_search_result_entry(message: &[u8]) -> io::Result<SearchEntry> {
    let (tag, content, _) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    let (id_tag, _, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    let (op_tag, op, _) = read_tlv(rest)?;
    if op_tag != TAG_SEARCH_RESULT_ENTRY {
        return Err(invalid("expected SearchResultEntry"));
    }
    let (n_tag, name, after_name) = read_tlv(op)?;
    if n_tag != TAG_OCTET_STRING {
        return Err(invalid("expected objectName"));
    }
    let object_name =
        String::from_utf8(name.to_vec()).map_err(|_| invalid("objectName is not UTF-8"))?;
    let (list_tag, list, _) = read_tlv(after_name)?;
    if list_tag != TAG_SEQUENCE {
        return Err(invalid("expected PartialAttributeList SEQUENCE"));
    }
    let mut attributes = Vec::new();
    let mut cur = list;
    while !cur.is_empty() {
        let (atag, acontent, rest) = read_tlv(cur)?;
        if atag != TAG_SEQUENCE {
            return Err(invalid("expected PartialAttribute SEQUENCE"));
        }
        let (t_tag, tbytes, after_t) = read_tlv(acontent)?;
        if t_tag != TAG_OCTET_STRING {
            return Err(invalid("expected AttributeDescription"));
        }
        let type_ =
            String::from_utf8(tbytes.to_vec()).map_err(|_| invalid("attr type is not UTF-8"))?;
        let (set_tag, set, _) = read_tlv(after_t)?;
        if set_tag != TAG_SET {
            return Err(invalid("expected vals SET"));
        }
        let mut values = Vec::new();
        let mut sc = set;
        while !sc.is_empty() {
            let (v_tag, v, vrest) = read_tlv(sc)?;
            if v_tag != TAG_OCTET_STRING {
                return Err(invalid("expected AttributeValue OCTET STRING"));
            }
            let s =
                String::from_utf8(v.to_vec()).map_err(|_| invalid("attr value is not UTF-8"))?;
            values.push(s);
            sc = vrest;
        }
        attributes.push(PartialAttribute { type_, values });
        cur = rest;
    }
    Ok(SearchEntry {
        object_name,
        attributes,
    })
}

/// Decode SearchResultDone `resultCode`.
pub fn parse_search_result_done(message: &[u8]) -> io::Result<i64> {
    let (tag, content, _) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    let (id_tag, _, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    let (op_tag, op, _) = read_tlv(rest)?;
    if op_tag != TAG_SEARCH_RESULT_DONE {
        return Err(invalid("expected SearchResultDone"));
    }
    let (rc_tag, rc, _) = read_tlv(op)?;
    if rc_tag != TAG_ENUMERATED {
        return Err(invalid("expected resultCode ENUMERATED"));
    }
    decode_integer(rc)
}

/// Classify the first protocolOp tag of an LDAPMessage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchPduKind {
    Entry,
    Done,
    Reference,
    Other,
}

/// Inspect the protocolOp tag without fully parsing the PDU.
pub fn search_pdu_kind(message: &[u8]) -> io::Result<SearchPduKind> {
    let (tag, content, _) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    let (id_tag, _, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    let (op_tag, _, _) = read_tlv(rest)?;
    Ok(match op_tag {
        TAG_SEARCH_RESULT_ENTRY => SearchPduKind::Entry,
        TAG_SEARCH_RESULT_DONE => SearchPduKind::Done,
        TAG_SEARCH_RESULT_REFERENCE => SearchPduKind::Reference,
        _ => SearchPduKind::Other,
    })
}

/// Encode a SearchResultEntry (test directory).
#[must_use]
pub fn encode_search_result_entry(message_id: i64, entry: &SearchEntry) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, entry.object_name.as_bytes()));
    let mut list = Vec::new();
    for attr in &entry.attributes {
        let mut one = Vec::new();
        one.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, attr.type_.as_bytes()));
        let mut set = Vec::new();
        for v in &attr.values {
            set.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, v.as_bytes()));
        }
        one.extend_from_slice(&encode_tlv(TAG_SET, &set));
        list.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &one));
    }
    body.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &list));
    let op = encode_tlv(TAG_SEARCH_RESULT_ENTRY, &body);
    let mut msg = Vec::new();
    msg.extend_from_slice(&encode_integer(message_id));
    msg.extend_from_slice(&op);
    encode_tlv(TAG_SEQUENCE, &msg)
}

/// Encode a SearchResultDone (test directory).
#[must_use]
pub fn encode_search_result_done(message_id: i64, result_code: i64) -> Vec<u8> {
    let mut body = Vec::new();
    let rc_int = encode_integer(result_code);
    body.extend_from_slice(&encode_tlv(TAG_ENUMERATED, &rc_int[2..]));
    body.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, b""));
    body.extend_from_slice(&encode_tlv(TAG_OCTET_STRING, b""));
    let op = encode_tlv(TAG_SEARCH_RESULT_DONE, &body);
    let mut msg = Vec::new();
    msg.extend_from_slice(&encode_integer(message_id));
    msg.extend_from_slice(&op);
    encode_tlv(TAG_SEQUENCE, &msg)
}

/// Parse a SearchRequest (test directory).
pub fn parse_search_request(
    message: &[u8],
) -> io::Result<(i64, String, bool, SearchFilter, Vec<String>)> {
    let (tag, content, _) = read_tlv(message)?;
    if tag != TAG_SEQUENCE {
        return Err(invalid("expected LDAPMessage SEQUENCE"));
    }
    let (id_tag, id_bytes, rest) = read_tlv(content)?;
    if id_tag != TAG_INTEGER {
        return Err(invalid("expected messageID INTEGER"));
    }
    let message_id = decode_integer(id_bytes)?;
    let (op_tag, op, _) = read_tlv(rest)?;
    if op_tag != TAG_SEARCH_REQUEST {
        return Err(invalid("expected SearchRequest"));
    }
    let (b_tag, base, after_base) = read_tlv(op)?;
    if b_tag != TAG_OCTET_STRING {
        return Err(invalid("expected baseObject"));
    }
    let base = String::from_utf8(base.to_vec()).map_err(|_| invalid("base is not UTF-8"))?;
    let (s_tag, s_bytes, after_scope) = read_tlv(after_base)?;
    if s_tag != TAG_ENUMERATED {
        return Err(invalid("expected scope"));
    }
    let subtree = decode_integer(s_bytes)? == 2;
    let (_, _, after_deref) = read_tlv(after_scope)?;
    let (_, _, after_size) = read_tlv(after_deref)?;
    let (_, _, after_time) = read_tlv(after_size)?;
    let (_, _, after_types) = read_tlv(after_time)?;
    let (f_tag, f_content, after_filter) = read_tlv(after_types)?;
    let filter = match f_tag {
        TAG_FILTER_PRESENT => {
            let attr =
                String::from_utf8(f_content.to_vec()).map_err(|_| invalid("present attr"))?;
            SearchFilter::Present(attr)
        }
        TAG_FILTER_EQUALITY => {
            let (a_tag, a, after_a) = read_tlv(f_content)?;
            if a_tag != TAG_OCTET_STRING {
                return Err(invalid("equality attr"));
            }
            let (v_tag, v, _) = read_tlv(after_a)?;
            if v_tag != TAG_OCTET_STRING {
                return Err(invalid("equality value"));
            }
            SearchFilter::Equality {
                attr: String::from_utf8(a.to_vec()).map_err(|_| invalid("eq attr utf8"))?,
                value: String::from_utf8(v.to_vec()).map_err(|_| invalid("eq val utf8"))?,
            }
        }
        _ => return Err(invalid("unsupported search filter")),
    };
    let (list_tag, list, _) = read_tlv(after_filter)?;
    if list_tag != TAG_SEQUENCE {
        return Err(invalid("expected attributes SEQUENCE"));
    }
    let mut attributes = Vec::new();
    let mut cur = list;
    while !cur.is_empty() {
        let (t, v, rest) = read_tlv(cur)?;
        if t != TAG_OCTET_STRING {
            return Err(invalid("expected attribute name"));
        }
        attributes.push(String::from_utf8(v.to_vec()).map_err(|_| invalid("attr name utf8"))?);
        cur = rest;
    }
    Ok((message_id, base, subtree, filter, attributes))
}

/// Outcome of collecting keys from one search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchCollect {
    Complete(Vec<String>),
    IncompleteNotFound,
    IncompleteUnreachable,
}

/// Drive a SearchRequest on `stream` and collect keys.
pub fn search_collect_on_stream<S: Read + Write>(
    stream: &mut S,
    message_id: i64,
    base: &str,
    subtree: bool,
    filter: &SearchFilter,
    attributes: &[&str],
    key_from_entry: impl Fn(&SearchEntry) -> Vec<String>,
) -> io::Result<SearchCollect> {
    let req = encode_search_request(message_id, base, subtree, filter, attributes);
    stream.write_all(&req)?;
    stream.flush()?;

    let mut keys = Vec::new();
    let mut saw_entry = false;
    let mut saw_only_referral = false;
    loop {
        let pdu = read_ldap_message_max(stream, MAX_SEARCH_LDAP_MESSAGE)?;
        match search_pdu_kind(&pdu)? {
            SearchPduKind::Reference => {
                saw_only_referral = !saw_entry;
            }
            SearchPduKind::Entry => {
                let entry = parse_search_result_entry(&pdu)?;
                if entry.has_range_attribute() {
                    return Ok(SearchCollect::IncompleteUnreachable);
                }
                saw_entry = true;
                saw_only_referral = false;
                keys.extend(key_from_entry(&entry));
            }
            SearchPduKind::Done => {
                let code = parse_search_result_done(&pdu)?;
                return Ok(classify_search_done(
                    code,
                    saw_entry,
                    saw_only_referral,
                    keys,
                ));
            }
            SearchPduKind::Other => return Err(invalid("unexpected LDAP protocolOp in search")),
        }
    }
}

fn classify_search_done(
    code: i64,
    saw_entry: bool,
    saw_only_referral: bool,
    keys: Vec<String>,
) -> SearchCollect {
    match code {
        LDAP_SUCCESS => {
            if saw_only_referral && !saw_entry {
                SearchCollect::IncompleteUnreachable
            } else {
                SearchCollect::Complete(keys)
            }
        }
        LDAP_NO_SUCH_OBJECT | LDAP_INSUFFICIENT_ACCESS => SearchCollect::IncompleteNotFound,
        _ => SearchCollect::IncompleteUnreachable,
    }
}

/// Execute the compiled resolve plan on an already-bound stream. Any
/// incomplete line fails the whole collection (no silent subset).
pub fn collect_resolve_plan<S: Read + Write>(
    stream: &mut S,
    user_dn: &str,
    plan: &shared::ldap_mapping::ResolvePlan,
) -> io::Result<SearchCollect> {
    use shared::ldap_mapping::{GroupKeyKind, ResolveLine};

    let mut keys = Vec::new();
    let mut saw_not_found = false;
    for (i, line) in plan.lines.iter().enumerate() {
        let message_id = i64::try_from(i)
            .ok()
            .and_then(|n| n.checked_add(2))
            .unwrap_or(2);
        let collect = match line {
            ResolveLine::UserAttr { attr } => search_collect_on_stream(
                stream,
                message_id,
                user_dn,
                false,
                &SearchFilter::Present("objectClass".into()),
                &[attr.as_str()],
                |entry| entry.values_of(attr),
            )?,
            ResolveLine::GroupAttr { attr, base, key } => search_collect_on_stream(
                stream,
                message_id,
                base,
                true,
                &SearchFilter::Equality {
                    attr: attr.clone(),
                    value: user_dn.to_string(),
                },
                match key {
                    GroupKeyKind::Mail => &["mail"][..],
                    GroupKeyKind::Dn => &[][..],
                },
                |entry| match key {
                    GroupKeyKind::Mail => entry.values_of("mail"),
                    GroupKeyKind::Dn => vec![entry.object_name.clone()],
                },
            )?,
        };
        match collect {
            SearchCollect::Complete(found) => {
                for k in found {
                    if !push_group_key(&mut keys, &k) {
                        return Ok(SearchCollect::IncompleteUnreachable);
                    }
                }
            }
            SearchCollect::IncompleteNotFound => saw_not_found = true,
            SearchCollect::IncompleteUnreachable => {
                return Ok(SearchCollect::IncompleteUnreachable);
            }
        }
    }
    if saw_not_found {
        return Ok(SearchCollect::IncompleteNotFound);
    }
    Ok(SearchCollect::Complete(keys))
}

/// Push `candidate` into `keys` honouring the 1024 / 192 KiB / 512 B caps.
/// Returns `false` when the key list overflowed (case C).
pub fn push_group_key(keys: &mut Vec<String>, candidate: &str) -> bool {
    if candidate.len() > MAX_GROUP_KEY_BYTES {
        return false;
    }
    if keys.len() >= MAX_GROUP_KEYS {
        return false;
    }
    let used: usize = keys.iter().map(|k| k.len()).sum();
    if used.saturating_add(candidate.len()) > MAX_GROUP_KEYS_BYTES {
        return false;
    }
    if !keys.iter().any(|k| k == candidate) {
        keys.push(candidate.to_string());
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockStream {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(response: Vec<u8>) -> Self {
            Self {
                to_read: Cursor::new(response),
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bind_request_is_well_formed_ber() {
        let req = encode_bind_request(1, "cn=admin,dc=example,dc=com", b"s3cret");
        // Outer LDAPMessage SEQUENCE.
        let (tag, content, rest) = read_tlv(&req).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert!(rest.is_empty(), "no trailing bytes after the message");
        // messageID INTEGER = 1.
        let (id_tag, id, after_id) = read_tlv(content).unwrap();
        assert_eq!(id_tag, TAG_INTEGER);
        assert_eq!(decode_integer(id).unwrap(), 1);
        // BindRequest [APPLICATION 0].
        let (br_tag, br, _) = read_tlv(after_id).unwrap();
        assert_eq!(br_tag, TAG_BIND_REQUEST);
        // version INTEGER = 3.
        let (v_tag, v, after_v) = read_tlv(br).unwrap();
        assert_eq!(v_tag, TAG_INTEGER);
        assert_eq!(decode_integer(v).unwrap(), 3);
        // name OCTET STRING = DN.
        let (n_tag, n, after_n) = read_tlv(after_v).unwrap();
        assert_eq!(n_tag, TAG_OCTET_STRING);
        assert_eq!(n, b"cn=admin,dc=example,dc=com");
        // [0] simple password.
        let (p_tag, p, _) = read_tlv(after_n).unwrap();
        assert_eq!(p_tag, TAG_SIMPLE_AUTH);
        assert_eq!(p, b"s3cret");
    }

    #[test]
    fn bind_request_handles_long_form_length() {
        // A long DN forces the long-form length encoding (> 127 bytes).
        let dn = "cn=".to_string() + &"x".repeat(200) + ",dc=example,dc=com";
        let req = encode_bind_request(1, &dn, b"pw");
        let (tag, content, _) = read_tlv(&req).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        // Walk to the DN and confirm it survived the round-trip.
        let (_, _, after_id) = read_tlv(content).unwrap();
        let (_, br, _) = read_tlv(after_id).unwrap();
        let (_, _, after_v) = read_tlv(br).unwrap();
        let (n_tag, n, _) = read_tlv(after_v).unwrap();
        assert_eq!(n_tag, TAG_OCTET_STRING);
        assert_eq!(n, dn.as_bytes());
    }

    #[test]
    fn parse_bind_response_roundtrip_success_and_reject() {
        for code in [LDAP_SUCCESS, LDAP_INVALID_CREDENTIALS, 50, 53, 200] {
            let msg = encode_bind_response(7, code);
            assert_eq!(parse_bind_response(&msg).unwrap(), code, "code {code}");
        }
    }

    #[test]
    fn parse_bind_response_rejects_truncated() {
        let msg = encode_bind_response(1, LDAP_SUCCESS);
        for cut in 0..msg.len() {
            let truncated = &msg[..cut];
            assert!(
                parse_bind_response(truncated).is_err(),
                "truncation at {cut} must fail-closed"
            );
        }
    }

    #[test]
    fn parse_bind_response_rejects_wrong_outer_tag() {
        let mut msg = encode_bind_response(1, LDAP_SUCCESS);
        msg[0] = TAG_OCTET_STRING; // not a SEQUENCE
        assert!(parse_bind_response(&msg).is_err());
    }

    #[test]
    fn parse_bind_response_rejects_non_bind_response_protocol_op() {
        // Build a SEQUENCE { INTEGER, SEQUENCE{...} } where protocolOp is a
        // plain SEQUENCE rather than [APPLICATION 1].
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_integer(1));
        inner.extend_from_slice(&encode_tlv(TAG_SEQUENCE, &encode_tlv(TAG_ENUMERATED, &[0])));
        let msg = encode_tlv(TAG_SEQUENCE, &inner);
        assert!(parse_bind_response(&msg).is_err());
    }

    #[test]
    fn decode_length_rejects_indefinite_and_oversized() {
        assert!(decode_length(&[0x80]).is_err());
        // Long form announcing 0x01_00_00_00 (16 MiB) > MAX.
        assert!(decode_length(&[0x84, 0x01, 0x00, 0x00, 0x00]).is_err());
        // Long form wider than 4 bytes.
        assert!(decode_length(&[0x85, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn read_ldap_message_reads_exactly_one_message() {
        let msg = encode_bind_response(3, LDAP_SUCCESS);
        // Append trailing junk; the reader must consume only the framed bytes.
        let mut buf = msg.clone();
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let mut cursor = Cursor::new(buf);
        let read = read_ldap_message(&mut cursor).unwrap();
        assert_eq!(read, msg);
        assert_eq!(parse_bind_response(&read).unwrap(), LDAP_SUCCESS);
    }

    #[test]
    fn read_ldap_message_rejects_indefinite_length() {
        let mut cursor = Cursor::new(vec![TAG_SEQUENCE, 0x80]);
        assert!(read_ldap_message(&mut cursor).is_err());
    }

    #[test]
    fn read_ldap_message_rejects_oversized_length() {
        // SEQUENCE with long-form length = 0x00FFFFFF (> MAX_LDAP_MESSAGE).
        let mut cursor = Cursor::new(vec![TAG_SEQUENCE, 0x83, 0xff, 0xff, 0xff]);
        assert!(read_ldap_message(&mut cursor).is_err());
    }

    #[test]
    fn read_ldap_message_rejects_truncated_content() {
        // Announces 10 content bytes but provides only 3.
        let mut cursor = Cursor::new(vec![TAG_SEQUENCE, 0x0a, 1, 2, 3]);
        assert!(read_ldap_message(&mut cursor).is_err());
    }

    #[test]
    fn simple_bind_on_stream_writes_request_and_reads_result() {
        let response = encode_bind_response(1, LDAP_SUCCESS);
        let mut stream = MockStream::new(response);
        let code = simple_bind_on_stream(&mut stream, "uid=bob,dc=ex,dc=com", b"pw").unwrap();
        assert_eq!(code, LDAP_SUCCESS);
        // The written bytes must be a valid BindRequest for the same DN.
        let (tag, _content, _) = read_tlv(&stream.written).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert!(
            stream
                .written
                .windows(20)
                .any(|w| w == b"uid=bob,dc=ex,dc=com"),
            "request must embed the bind DN"
        );
    }

    #[test]
    fn simple_bind_on_stream_reports_invalid_credentials() {
        let response = encode_bind_response(1, LDAP_INVALID_CREDENTIALS);
        let mut stream = MockStream::new(response);
        let code = simple_bind_on_stream(&mut stream, "uid=bob", b"wrong").unwrap();
        assert_eq!(code, LDAP_INVALID_CREDENTIALS);
    }

    #[test]
    fn simple_bind_on_stream_fails_closed_on_empty_response() {
        let mut stream = MockStream::new(Vec::new());
        assert!(simple_bind_on_stream(&mut stream, "uid=bob", b"pw").is_err());
    }

    #[test]
    fn bind_request_parses_back_to_dn_and_password() {
        let req = encode_bind_request(5, "uid=alice,dc=ex,dc=com", b"hunter2");
        let (id, dn, pw) = parse_bind_request(&req).unwrap();
        assert_eq!(id, 5);
        assert_eq!(dn, "uid=alice,dc=ex,dc=com");
        assert_eq!(pw, b"hunter2");
    }

    #[test]
    fn parse_bind_request_rejects_garbage() {
        assert!(parse_bind_request(&[0x30, 0x00]).is_err());
        assert!(parse_bind_request(b"not ber").is_err());
    }

    #[test]
    fn public_encode_bind_response_roundtrips() {
        for code in [0i64, 49, 50, 200] {
            let msg = encode_bind_response(9, code);
            assert_eq!(parse_bind_response(&msg).unwrap(), code);
        }
    }

    #[test]
    fn integer_roundtrip_minimal_encoding() {
        for v in [0i64, 1, 3, 49, 127, 128, 255, 256, 32767, -1, -128] {
            let tlv = encode_integer(v);
            let (tag, val, _) = read_tlv(&tlv).unwrap();
            assert_eq!(tag, TAG_INTEGER);
            assert_eq!(decode_integer(val).unwrap(), v, "value {v}");
        }
    }

    #[test]
    fn search_request_roundtrip_equality() {
        let req = encode_search_request(
            4,
            "OU=groups,DC=x",
            true,
            &SearchFilter::Equality {
                attr: "member".into(),
                value: "uid=alice,dc=x".into(),
            },
            &["mail"],
        );
        let (id, base, subtree, filter, attrs) = parse_search_request(&req).unwrap();
        assert_eq!(id, 4);
        assert_eq!(base, "OU=groups,DC=x");
        assert!(subtree);
        match filter {
            SearchFilter::Equality { attr, value } => {
                assert_eq!(attr, "member");
                assert_eq!(value, "uid=alice,dc=x");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(attrs, vec!["mail".to_string()]);
    }

    #[test]
    fn search_entry_roundtrip_and_range_detect() {
        let entry = SearchEntry {
            object_name: "CN=Ops,DC=x".into(),
            attributes: vec![PartialAttribute {
                type_: "memberOf;range=0-1499".into(),
                values: vec!["CN=A,DC=x".into()],
            }],
        };
        let msg = encode_search_result_entry(2, &entry);
        let parsed = parse_search_result_entry(&msg).unwrap();
        assert!(parsed.has_range_attribute());
        assert_eq!(parsed.values_of("memberOf"), vec!["CN=A,DC=x".to_string()]);
    }

    #[test]
    fn attack_range_attribute_is_not_silently_absent() {
        let entry = SearchEntry {
            object_name: "uid=alice,dc=x".into(),
            attributes: vec![PartialAttribute {
                type_: "memberOf;range=0-1499".into(),
                values: vec!["CN=Subset,DC=x".into()],
            }],
        };
        assert!(
            entry.has_range_attribute(),
            "truncated memberOf must be visible to the collector"
        );
    }

    #[test]
    fn search_insufficient_access_is_not_entry_not_found() {
        // classify_search_done maps both to IncompleteNotFound (case B).
        // Unreachable (timeout / other code) stays distinct.
        let not_found = classify_search_done(LDAP_NO_SUCH_OBJECT, false, false, Vec::new());
        let denied = classify_search_done(LDAP_INSUFFICIENT_ACCESS, false, false, Vec::new());
        let boom = classify_search_done(80, false, false, Vec::new());
        assert_eq!(not_found, SearchCollect::IncompleteNotFound);
        assert_eq!(denied, SearchCollect::IncompleteNotFound);
        assert_eq!(boom, SearchCollect::IncompleteUnreachable);
    }

    #[test]
    fn search_unreachable_is_not_treated_as_entry_not_found() {
        assert_eq!(
            classify_search_done(3, false, false, Vec::new()),
            SearchCollect::IncompleteUnreachable
        );
    }

    #[test]
    fn referral_only_is_incomplete_unreachable() {
        assert_eq!(
            classify_search_done(LDAP_SUCCESS, false, true, Vec::new()),
            SearchCollect::IncompleteUnreachable
        );
    }

    #[test]
    fn malformed_search_pdu_is_io_error() {
        assert!(parse_search_result_entry(&[0xff, 0x00]).is_err());
        assert!(parse_search_result_done(b"nope").is_err());
        assert!(search_pdu_kind(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn push_group_key_caps_overflow() {
        let mut keys = Vec::new();
        assert!(push_group_key(&mut keys, "CN=A,DC=x"));
        assert!(!push_group_key(
            &mut keys,
            &"x".repeat(MAX_GROUP_KEY_BYTES + 1)
        ));
        keys = (0..MAX_GROUP_KEYS).map(|i| format!("k{i}")).collect();
        assert!(!push_group_key(&mut keys, "overflow"));
    }
}
