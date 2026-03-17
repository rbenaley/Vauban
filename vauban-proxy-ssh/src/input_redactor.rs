//! Two-layer password detection engine for SSH input redaction.
//!
//! Combines pattern matching (known password prompts in server output) with
//! echo suppression detection (printable input not echoed back) to identify
//! sensitive input that must be redacted from recordings.

const PASSWORD_PATTERNS: &[&str] = &[
    "password:",
    "passphrase",
    "[sudo]",
    "enter pin",
    "verification code",
    "token:",
    "secret:",
    "become password",
    "login:",
];

const ECHO_SUPPRESSION_THRESHOLD: usize = 3;

/// Two-layer password detection engine.
///
/// Layer 1 (pattern): scans server output for known password prompt patterns.
/// Layer 2 (echo suppression): detects when printable input is not echoed back
/// by the server, indicating the remote side has disabled echo (e.g. `ECHO` flag
/// cleared in `termios`).
pub struct InputRedactor {
    pattern_triggered: bool,
    unechoed_printable_count: usize,
    echo_suppressed: bool,
    recent_input: Vec<u8>,
    suppressing: bool,
}

impl InputRedactor {
    pub fn new() -> Self {
        Self {
            pattern_triggered: false,
            unechoed_printable_count: 0,
            echo_suppressed: false,
            recent_input: Vec::new(),
            suppressing: false,
        }
    }

    /// Analyze server output for password prompts and echo detection.
    pub fn on_server_output(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data).to_lowercase();

        for pattern in PASSWORD_PATTERNS {
            if text.contains(pattern) {
                self.pattern_triggered = true;
                self.suppressing = true;
                break;
            }
        }

        if !self.recent_input.is_empty() {
            let echoed = data
                .windows(1)
                .any(|w| self.recent_input.contains(&w[0]) && w[0].is_ascii_graphic());
            if echoed {
                self.unechoed_printable_count = 0;
            }
        }
    }

    /// Track user input for echo suppression detection.
    pub fn on_user_input(&mut self, data: &[u8]) {
        for &b in data {
            if b == b'\r' || b == b'\n' {
                return;
            }
            if b.is_ascii_graphic() || b == b' ' {
                self.recent_input.push(b);
                self.unechoed_printable_count += 1;
                if self.unechoed_printable_count >= ECHO_SUPPRESSION_THRESHOLD {
                    self.echo_suppressed = true;
                    self.suppressing = true;
                }
            }
        }
    }

    /// Process input for recording, returning redacted or passthrough data.
    ///
    /// Returns `None` when input is being accumulated during suppression.
    /// Returns `Some(b"[REDACTED]\r\n")` when Enter is pressed during suppression.
    /// Returns `Some(data)` for normal (non-suppressed) input.
    pub fn process_input_for_recording(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let has_newline = data.iter().any(|&b| b == b'\r' || b == b'\n');

        if self.suppressing {
            if has_newline {
                let result = b"[REDACTED]\r\n".to_vec();
                self.reset();
                return Some(result);
            }
            return None;
        }

        Some(data.to_vec())
    }

    fn reset(&mut self) {
        self.pattern_triggered = false;
        self.echo_suppressed = false;
        self.suppressing = false;
        self.unechoed_printable_count = 0;
        self.recent_input.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_input_passes_through() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"$ ");
        r.on_user_input(b"l");
        r.on_server_output(b"l");
        let result = r.process_input_for_recording(b"l");
        assert_eq!(result, Some(b"l".to_vec()));
    }

    #[test]
    fn test_password_colon_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Password: ");
        r.on_user_input(b"s");
        let result = r.process_input_for_recording(b"s");
        assert_eq!(result, None);
    }

    #[test]
    fn test_sudo_prompt_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"[sudo] password for user: ");
        r.on_user_input(b"x");
        let result = r.process_input_for_recording(b"x");
        assert_eq!(result, None);
    }

    #[test]
    fn test_passphrase_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Enter passphrase for key '/home/user/.ssh/id_rsa': ");
        r.on_user_input(b"k");
        let result = r.process_input_for_recording(b"k");
        assert_eq!(result, None);
    }

    #[test]
    fn test_case_insensitive_pattern_matching() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"PASSWORD:");
        r.on_user_input(b"a");
        assert_eq!(r.process_input_for_recording(b"a"), None);

        let mut r2 = InputRedactor::new();
        r2.on_server_output(b"Password:");
        r2.on_user_input(b"b");
        assert_eq!(r2.process_input_for_recording(b"b"), None);
    }

    #[test]
    fn test_redaction_emits_on_newline() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Password: ");
        r.on_user_input(b"secret");
        assert_eq!(r.process_input_for_recording(b"secret"), None);
        r.on_user_input(b"\r");
        let result = r.process_input_for_recording(b"\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_redaction_resets_after_newline() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Password: ");
        r.on_user_input(b"secret\r");
        let _ = r.process_input_for_recording(b"secret\r");

        r.on_server_output(b"$ ");
        r.on_user_input(b"l");
        r.on_server_output(b"l");
        let result = r.process_input_for_recording(b"l");
        assert_eq!(result, Some(b"l".to_vec()));
    }

    #[test]
    fn test_echo_suppression_detects_no_echo() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"custom prompt> ");
        r.on_user_input(b"a");
        r.on_user_input(b"b");
        r.on_user_input(b"c");
        r.on_user_input(b"d");
        r.on_user_input(b"e");
        assert!(r.suppressing);
        assert_eq!(r.process_input_for_recording(b"e"), None);
    }

    #[test]
    fn test_echo_present_no_suppression() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"$ ");
        r.on_user_input(b"l");
        r.on_server_output(b"l");
        r.on_user_input(b"s");
        r.on_server_output(b"s");
        r.on_user_input(b" ");
        r.on_server_output(b" ");
        assert!(!r.suppressing);
        let result = r.process_input_for_recording(b" ");
        assert_eq!(result, Some(b" ".to_vec()));
    }

    #[test]
    fn test_single_char_no_echo_no_suppression() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"$ ");
        r.on_user_input(b"x");
        assert!(!r.suppressing);
        let result = r.process_input_for_recording(b"x");
        assert_eq!(result, Some(b"x".to_vec()));
    }

    #[test]
    fn test_two_chars_no_echo_no_suppression() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"$ ");
        r.on_user_input(b"a");
        r.on_user_input(b"b");
        assert!(!r.suppressing);
        let result = r.process_input_for_recording(b"b");
        assert_eq!(result, Some(b"b".to_vec()));
    }

    #[test]
    fn test_three_chars_no_echo_triggers_suppression() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"hidden> ");
        r.on_user_input(b"a");
        r.on_user_input(b"b");
        r.on_user_input(b"c");
        assert!(r.suppressing);
        assert_eq!(r.process_input_for_recording(b"c"), None);
    }

    #[test]
    fn test_combined_pattern_and_echo() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Password: ");
        r.on_user_input(b"abc");
        assert_eq!(r.process_input_for_recording(b"abc"), None);
        r.on_user_input(b"\r");
        let result = r.process_input_for_recording(b"\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_pattern_without_echo_check() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Password: ");
        assert!(r.suppressing);
        r.on_user_input(b"x");
        let result = r.process_input_for_recording(b"x");
        assert_eq!(result, None);
    }

    #[test]
    fn test_echo_without_pattern() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"unknown> ");
        r.on_user_input(b"a");
        r.on_user_input(b"b");
        r.on_user_input(b"c");
        assert!(r.suppressing);
        r.on_user_input(b"\r");
        let result = r.process_input_for_recording(b"\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_multiple_password_prompts_in_sequence() {
        let mut r = InputRedactor::new();

        r.on_server_output(b"Password: ");
        r.on_user_input(b"pass1\r");
        let result = r.process_input_for_recording(b"pass1\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));

        r.on_server_output(b"Password: ");
        r.on_user_input(b"pass2\r");
        let result = r.process_input_for_recording(b"pass2\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_empty_input_no_crash() {
        let mut r = InputRedactor::new();
        r.on_user_input(b"");
        let result = r.process_input_for_recording(b"");
        assert_eq!(result, Some(b"".to_vec()));
    }

    #[test]
    fn test_output_only_no_input_no_crash() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Welcome to the server\r\n");
        r.on_server_output(b"Last login: Mon Mar 17 10:00:00 2026\r\n");
        r.on_server_output(b"$ ");
    }

    #[test]
    fn test_partial_pattern_no_trigger() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Pass");
        assert!(!r.suppressing);
        r.on_user_input(b"x");
        let result = r.process_input_for_recording(b"x");
        assert_eq!(result, Some(b"x".to_vec()));
    }

    #[test]
    fn test_multiline_output_with_pattern() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Connecting to server...\r\nAuthentication required.\r\nPassword: ");
        assert!(r.suppressing);
        r.on_user_input(b"secret\r");
        let result = r.process_input_for_recording(b"secret\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_verification_code_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Verification code: ");
        assert!(r.suppressing);
        r.on_user_input(b"123456\r");
        let result = r.process_input_for_recording(b"123456\r");
        assert_eq!(result, Some(b"[REDACTED]\r\n".to_vec()));
    }

    #[test]
    fn test_token_prompt_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Token: ");
        assert!(r.suppressing);
    }

    #[test]
    fn test_secret_prompt_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Enter secret: ");
        assert!(r.suppressing);
    }

    #[test]
    fn test_become_password_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"become password: ");
        assert!(r.suppressing);
    }

    #[test]
    fn test_login_prompt_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"login: ");
        assert!(r.suppressing);
    }

    #[test]
    fn test_enter_pin_triggers_redaction() {
        let mut r = InputRedactor::new();
        r.on_server_output(b"Enter PIN: ");
        assert!(r.suppressing);
    }
}
