//! Minimal, hand-rolled BER codec for the LDAP **simple bind** (RFC 4511).
//!
//! We implement only what an authentication bind needs: encode a
//! `BindRequest` (version 3, name = DN, simple authentication = password) and
//! decode the `resultCode` of the corresponding `BindResponse`. Everything
//! else (search, SASL, controls, referrals) is intentionally out of scope.
//!
//! Robustness contract: the decoder is **fail-closed**. Any malformed,
//! truncated, indefinite-length or oversized input yields an `io::Error`;
//! the decoder never panics and never allocates an attacker-controlled
//! amount of memory (see [`MAX_LDAP_MESSAGE`]).

use std::io::{self, Read, Write};

/// LDAP `resultCode` for a successful bind.
pub const LDAP_SUCCESS: i64 = 0;
/// LDAP `resultCode` for rejected credentials.
pub const LDAP_INVALID_CREDENTIALS: i64 = 49;

/// Hard upper bound on a single LDAP message we will buffer. A BindResponse
/// is tiny; this cap defends the decoder against a hostile / buggy directory
/// announcing an enormous length.
pub const MAX_LDAP_MESSAGE: usize = 64 * 1024;

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
/// (`0x80`), long forms wider than 4 bytes, and any length exceeding
/// [`MAX_LDAP_MESSAGE`].
fn decode_length(buf: &[u8]) -> io::Result<(usize, usize)> {
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
    if len > MAX_LDAP_MESSAGE {
        return Err(invalid("LDAP message length exceeds maximum"));
    }
    Ok((len, 1 + num))
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
    if content_len > MAX_LDAP_MESSAGE {
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
    let dn = String::from_utf8(dn_bytes.to_vec())
        .map_err(|_| invalid("bind DN is not valid UTF-8"))?;
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
            stream.written.windows(20).any(|w| w == b"uid=bob,dc=ex,dc=com"),
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
}
