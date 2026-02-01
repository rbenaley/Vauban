//! Test utility macros for VAUBAN.
//!
//! These macros replace `unwrap()`/`expect()` with proper error handling in tests.
//! They provide better error messages with file and line information.
//!
//! # Usage
//!
//! ```rust,ignore
//! use vauban_web::{unwrap_ok, unwrap_some, assert_ok, assert_some};
//!
//! fn test_example() {
//!     let result: Result<i32, &str> = Ok(42);
//!     let value = unwrap_ok!(result);
//!     assert_eq!(value, 42);
//!
//!     let option: Option<i32> = Some(42);
//!     let value = unwrap_some!(option);
//!     assert_eq!(value, 42);
//! }
//! ```

/// Unwrap a `Result`, failing the test with a descriptive message if `Err`.
///
/// # Examples
///
/// ```rust
/// use vauban_web::unwrap_ok;
///
/// let result: Result<i32, &str> = Ok(42);
/// let value = unwrap_ok!(result);
/// assert_eq!(value, 42);
///
/// // With custom message
/// let result: Result<i32, &str> = Ok(42);
/// let value = unwrap_ok!(result, "Failed to get value");
/// assert_eq!(value, 42);
/// ```
#[macro_export]
macro_rules! unwrap_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("{}:{} - Expected Ok, got Err: {:?}", file!(), line!(), e),
        }
    };
    ($expr:expr, $msg:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => panic!("{}:{} - {}: {:?}", file!(), line!(), $msg, e),
        }
    };
}

/// Unwrap an `Option`, failing the test with a descriptive message if `None`.
///
/// # Examples
///
/// ```rust
/// use vauban_web::unwrap_some;
///
/// let option: Option<i32> = Some(42);
/// let value = unwrap_some!(option);
/// assert_eq!(value, 42);
///
/// // With custom message
/// let option: Option<i32> = Some(42);
/// let value = unwrap_some!(option, "Expected a value");
/// assert_eq!(value, 42);
/// ```
#[macro_export]
macro_rules! unwrap_some {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => panic!("{}:{} - Expected Some, got None", file!(), line!()),
        }
    };
    ($expr:expr, $msg:expr) => {
        match $expr {
            Some(val) => val,
            None => panic!("{}:{} - {}: got None", file!(), line!(), $msg),
        }
    };
}

/// Assert that a `Result` is `Ok` and return the value.
///
/// This combines assertion and extraction in one step.
///
/// # Examples
///
/// ```rust
/// use vauban_web::assert_ok;
///
/// let result: Result<i32, &str> = Ok(42);
/// let value = assert_ok!(result);
/// assert_eq!(value, 42);
/// ```
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {{
        let result = $expr;
        match &result {
            Ok(_) => {}
            Err(e) => panic!("{}:{} - Expected Ok, got Err: {:?}", file!(), line!(), e),
        }
        // SAFETY: We just verified it's Ok above
        #[allow(clippy::unwrap_used)]
        result.unwrap()
    }};
}

/// Assert that an `Option` is `Some` and return the value.
///
/// This combines assertion and extraction in one step.
///
/// # Examples
///
/// ```rust
/// use vauban_web::assert_some;
///
/// let option: Option<i32> = Some(42);
/// let value = assert_some!(option);
/// assert_eq!(value, 42);
/// ```
#[macro_export]
macro_rules! assert_some {
    ($expr:expr) => {{
        let option = $expr;
        match &option {
            Some(_) => {}
            None => panic!("{}:{} - Expected Some, got None", file!(), line!()),
        }
        // SAFETY: We just verified it's Some above
        #[allow(clippy::unwrap_used)]
        option.unwrap()
    }};
}

/// Assert that a `Result` is `Err`.
///
/// # Examples
///
/// ```rust
/// use vauban_web::assert_err;
///
/// let result: Result<i32, &str> = Err("error");
/// assert_err!(result);
/// ```
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {{
        let result = $expr;
        if result.is_ok() {
            panic!(
                "{}:{} - Expected Err, got Ok: {:?}",
                file!(),
                line!(),
                result.ok()
            );
        }
    }};
}

/// Assert that an `Option` is `None`.
///
/// # Examples
///
/// ```rust
/// use vauban_web::assert_none;
///
/// let option: Option<i32> = None;
/// assert_none!(option);
/// ```
#[macro_export]
macro_rules! assert_none {
    ($expr:expr) => {{
        let option = $expr;
        if option.is_some() {
            panic!(
                "{}:{} - Expected None, got Some: {:?}",
                file!(),
                line!(),
                option
            );
        }
    }};
}

#[cfg(test)]
mod tests {
    // ==================== unwrap_ok! Tests ====================

    #[test]
    fn test_unwrap_ok_with_ok() {
        let result: Result<i32, &str> = Ok(42);
        let value = unwrap_ok!(result);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_unwrap_ok_with_message() {
        let result: Result<i32, &str> = Ok(42);
        let value = unwrap_ok!(result, "Failed to get value");
        assert_eq!(value, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Ok, got Err")]
    fn test_unwrap_ok_with_err_panics() {
        let result: Result<i32, &str> = Err("error");
        let _ = unwrap_ok!(result);
    }

    #[test]
    #[should_panic(expected = "Custom message")]
    fn test_unwrap_ok_with_err_and_message_panics() {
        let result: Result<i32, &str> = Err("error");
        let _ = unwrap_ok!(result, "Custom message");
    }

    // ==================== unwrap_some! Tests ====================

    #[test]
    fn test_unwrap_some_with_some() {
        let option: Option<i32> = Some(42);
        let value = unwrap_some!(option);
        assert_eq!(value, 42);
    }

    #[test]
    fn test_unwrap_some_with_message() {
        let option: Option<i32> = Some(42);
        let value = unwrap_some!(option, "Expected a value");
        assert_eq!(value, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Some, got None")]
    fn test_unwrap_some_with_none_panics() {
        let option: Option<i32> = None;
        let _ = unwrap_some!(option);
    }

    #[test]
    #[should_panic(expected = "Custom message")]
    fn test_unwrap_some_with_none_and_message_panics() {
        let option: Option<i32> = None;
        let _ = unwrap_some!(option, "Custom message");
    }

    // ==================== assert_ok! Tests ====================

    #[test]
    fn test_assert_ok_with_ok() {
        let result: Result<i32, &str> = Ok(42);
        let value = assert_ok!(result);
        assert_eq!(value, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Ok, got Err")]
    fn test_assert_ok_with_err_panics() {
        let result: Result<i32, &str> = Err("error");
        let _ = assert_ok!(result);
    }

    // ==================== assert_some! Tests ====================

    #[test]
    fn test_assert_some_with_some() {
        let option: Option<i32> = Some(42);
        let value = assert_some!(option);
        assert_eq!(value, 42);
    }

    #[test]
    #[should_panic(expected = "Expected Some, got None")]
    fn test_assert_some_with_none_panics() {
        let option: Option<i32> = None;
        let _ = assert_some!(option);
    }

    // ==================== assert_err! Tests ====================

    #[test]
    fn test_assert_err_with_err() {
        let result: Result<i32, &str> = Err("error");
        assert_err!(result);
    }

    #[test]
    #[should_panic(expected = "Expected Err, got Ok")]
    fn test_assert_err_with_ok_panics() {
        let result: Result<i32, &str> = Ok(42);
        assert_err!(result);
    }

    // ==================== assert_none! Tests ====================

    #[test]
    fn test_assert_none_with_none() {
        let option: Option<i32> = None;
        assert_none!(option);
    }

    #[test]
    #[should_panic(expected = "Expected None, got Some")]
    fn test_assert_none_with_some_panics() {
        let option: Option<i32> = Some(42);
        assert_none!(option);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_unwrap_ok_with_complex_type() {
        let result: Result<Vec<String>, std::io::Error> = Ok(vec!["hello".to_string()]);
        let value = unwrap_ok!(result);
        assert_eq!(value.len(), 1);
    }

    #[test]
    fn test_unwrap_some_with_complex_type() {
        let option: Option<Vec<i32>> = Some(vec![1, 2, 3]);
        let value = unwrap_some!(option);
        assert_eq!(value.len(), 3);
    }

    #[test]
    fn test_assert_ok_returns_value() {
        let result: Result<String, &str> = Ok("hello".to_string());
        let value = assert_ok!(result);
        assert_eq!(value, "hello");
    }

    #[test]
    fn test_assert_some_returns_value() {
        let option: Option<String> = Some("world".to_string());
        let value = assert_some!(option);
        assert_eq!(value, "world");
    }
}
