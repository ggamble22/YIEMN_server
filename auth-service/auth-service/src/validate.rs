//! Input validation and normalisation.

use crate::error::ApiError;

pub const PASSWORD_MIN_CHARS: usize = 8;
pub const PASSWORD_MAX_CHARS: usize = 128;
pub const DISPLAY_NAME_MAX_CHARS: usize = 64;

pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Pragmatic email check. Real verification belongs in an email-confirmation flow.
pub fn email(raw: &str) -> Result<String, ApiError> {
    let email = normalize_email(raw);
    let well_formed = email.len() <= 254
        && !email.contains(char::is_whitespace)
        && match email.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && local.len() <= 64
                    && !domain.contains('@')
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && !domain.contains("..")
            }
            None => false,
        };
    if well_formed {
        Ok(email)
    } else {
        Err(ApiError::Validation("email is not a valid address".into()))
    }
}

pub fn password(pw: &str) -> Result<(), ApiError> {
    let n = pw.chars().count();
    if !(PASSWORD_MIN_CHARS..=PASSWORD_MAX_CHARS).contains(&n) {
        return Err(ApiError::Validation(format!(
            "password must be {PASSWORD_MIN_CHARS}-{PASSWORD_MAX_CHARS} characters"
        )));
    }
    Ok(())
}

pub fn display_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    let n = name.chars().count();
    if n == 0 || n > DISPLAY_NAME_MAX_CHARS || name.chars().any(char::is_control) {
        return Err(ApiError::Validation(format!(
            "display_name must be 1-{DISPLAY_NAME_MAX_CHARS} printable characters"
        )));
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails() {
        assert_eq!(email("  Ada@Example.COM ").unwrap(), "ada@example.com");
        for bad in [
            "",
            "no-at",
            "a@b",
            "@x.com",
            "a@.com",
            "a@x.com.",
            "a b@x.com",
            "a@@x.com",
            "a@x..com",
        ] {
            assert!(email(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn passwords() {
        assert!(password("short").is_err());
        assert!(password("long enough").is_ok());
        assert!(password(&"x".repeat(129)).is_err());
    }

    #[test]
    fn display_names() {
        assert_eq!(display_name("  Ada  ").unwrap(), "Ada");
        assert!(display_name("   ").is_err());
        assert!(display_name("bad\u{0007}").is_err());
    }
}
