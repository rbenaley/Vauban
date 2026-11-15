//! Why an MCP visit ends when its access rule is created, edited or deleted.
//!
//! The proxy receives [`wire_reason`]: the machine code, then the sentence.
//! The database and the agent read the sentence. A newline in the rule name
//! is folded to a space so it cannot split the wire form.

pub const REASON: &str = "access_rule_changed";

pub const SENTENCE_PREFIX: &str = "Session closed because the access rule ";

#[must_use]
pub fn sentence(rule_name: &str) -> String {
    let name = rule_name.replace(['\n', '\r'], " ");
    format!("{SENTENCE_PREFIX}\"{name}\" was changed. Open a new session to continue.")
}

/// `access_rule_changed`, then the sentence. The proxy splits on the newline.
#[must_use]
pub fn wire_reason(rule_name: &str) -> String {
    format!("{REASON}\n{}", sentence(rule_name))
}

/// The sentence, when `reason` is the wire form or the sentence itself.
#[must_use]
pub fn client_message(reason: &str) -> Option<&str> {
    if let Some(rest) = reason.strip_prefix(REASON)
        && let Some(rest) = rest.strip_prefix('\n')
        && !rest.is_empty()
    {
        return Some(rest);
    }
    if reason.starts_with(SENTENCE_PREFIX) {
        return Some(reason);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentence_names_the_rule_and_says_to_reopen() {
        let text = sentence("Lab rule");
        assert_eq!(
            text,
            "Session closed because the access rule \"Lab rule\" was changed. Open a new session to continue."
        );
        assert!(client_message(&text) == Some(text.as_str()));
        let wire = wire_reason("Lab rule");
        assert_eq!(client_message(&wire), Some(text.as_str()));
        assert!(client_message("asset_deleted").is_none());
        assert!(client_message("session_terminated").is_none());
    }

    #[test]
    fn a_newline_in_the_rule_name_cannot_split_the_wire_reason() {
        let wire = wire_reason("one\ntwo");
        let message = client_message(&wire).expect("sentence");
        assert!(message.contains("one two"));
        assert!(!message.contains('\n'));
    }
}
