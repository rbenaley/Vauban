//! Fail-closed RFC 4515 filter encoder.
//!
//! Search filters are a grammar. Concatenating a username, user DN, or
//! group DN into `(attr=…)` with `format!` lets a caller close the clause
//! and inject another (`alice)(uid=admin)`). Every assertion value MUST
//! go through [`equality_filter`]: the attribute is allowlisted, then
//! RFC 4515 specials in the value are encoded as `\HH` literals.

/// Error raised when a filter assertion cannot be built fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilterEncodeError {
    /// Attribute token is empty or not an RFC 4512 descriptor / OID.
    #[error("LDAP attribute name is not allowed in a filter")]
    IllegalAttribute,
    /// Assertion value is empty.
    #[error("LDAP filter assertion value is empty")]
    EmptyValue,
    /// Assertion value carries a non-ASCII or non-printable byte that
    /// is not one of the five RFC 4515 escaped specials.
    #[error("LDAP filter assertion value contains an illegal character")]
    IllegalValue,
}

/// RFC 4512 attribute descriptor (`letter [keychar]*`) or numeric OID.
fn attr_allowed(attr: &str) -> bool {
    if attr.is_empty() || attr.len() > 128 {
        return false;
    }
    if attr.chars().all(|c| c.is_ascii_digit() || c == '.')
        && attr.contains('.')
        && attr
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return true;
    }
    let mut chars = attr.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Escape one assertion value per RFC 4515 §3 (`* ( ) \ NUL` → `\HH`).
pub fn escape_assertion_value(value: &str) -> Result<String, FilterEncodeError> {
    if value.is_empty() {
        return Err(FilterEncodeError::EmptyValue);
    }
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            0x00 => out.push_str("\\00"),
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => return Err(FilterEncodeError::IllegalValue),
        }
    }
    Ok(out)
}

/// Build a single equality filter `(attr=value)` with a fail-closed value.
pub fn equality_filter(attr: &str, value: &str) -> Result<String, FilterEncodeError> {
    if !attr_allowed(attr) {
        return Err(FilterEncodeError::IllegalAttribute);
    }
    let escaped = escape_assertion_value(value)?;
    // attr is allowlisted; escaped is encoder output (no raw interpolation).
    Ok(format!("({attr}={escaped})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_plain_user_dn() {
        assert_eq!(
            equality_filter("member", "uid=alice,ou=people,dc=example,dc=com").unwrap(),
            "(member=uid=alice,ou=people,dc=example,dc=com)"
        );
    }

    #[test]
    fn encodes_rfc4515_specials_as_hex() {
        assert_eq!(
            equality_filter("member", "a*b(c)d\\e").unwrap(),
            "(member=a\\2ab\\28c\\29d\\5ce)"
        );
        let with_nul = format!("pre{}post", '\0');
        assert_eq!(
            equality_filter("member", &with_nul).unwrap(),
            "(member=pre\\00post)"
        );
    }

    /// A hostile DN that tries to close the clause and inject another
    /// filter is encoded as a single literal; the raw `)(` never appears.
    #[test]
    fn attack_filter_metacharacters_are_rejected() {
        let injected = "alice)(uid=admin";
        let filter = equality_filter("member", injected).expect("encodable ASCII");
        assert_eq!(filter, "(member=alice\\29\\28uid=admin)");
        assert!(!filter.contains(")("), "second clause must not appear");
        assert_eq!(filter.chars().filter(|c| *c == '(').count(), 1);
        assert_eq!(filter.chars().filter(|c| *c == ')').count(), 1);
    }

    #[test]
    fn rejects_empty_and_illegal_attr() {
        assert_eq!(
            equality_filter("", "alice"),
            Err(FilterEncodeError::IllegalAttribute)
        );
        assert_eq!(
            equality_filter("member)", "alice"),
            Err(FilterEncodeError::IllegalAttribute)
        );
        assert_eq!(
            equality_filter("mem ber", "alice"),
            Err(FilterEncodeError::IllegalAttribute)
        );
        assert_eq!(
            equality_filter("member", ""),
            Err(FilterEncodeError::EmptyValue)
        );
    }

    #[test]
    fn rejects_non_ascii_and_controls() {
        assert_eq!(
            equality_filter("member", "alicé"),
            Err(FilterEncodeError::IllegalValue)
        );
        assert_eq!(
            equality_filter("member", "alice\n"),
            Err(FilterEncodeError::IllegalValue)
        );
    }

    #[test]
    fn accepts_oid_attribute() {
        assert_eq!(
            equality_filter("2.5.4.31", "uid=alice,dc=x").unwrap(),
            "(2.5.4.31=uid=alice,dc=x)"
        );
    }
}
