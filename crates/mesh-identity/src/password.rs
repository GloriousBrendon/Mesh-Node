//! The password policy (weak passwords are refused, not just warned about)
//! and username rules. A stolen device plus a guessable password is a whole
//! identity lost, since every device holds the root key; so this check runs
//! inside the keystore, where no caller can skip it.

/// Fewest characters a password can have.
pub const MIN_PASSWORD_LEN: usize = 10;
/// Most characters a username can have.
pub const MAX_USERNAME_LEN: usize = 32;
/// zxcvbn's score is 0–4; 3 is "safely unguessable: moderate protection
/// from an offline slow-hash attack", which is what a stolen keystore faces.
const MIN_SCORE: u8 = 3;

/// What's wrong with a password, if anything; `Weak` carries a hint to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordVerdict {
    Ok,
    TooShort,
    ContainsUsername,
    Weak { hint: String },
}

impl PasswordVerdict {
    pub fn is_ok(&self) -> bool {
        *self == PasswordVerdict::Ok
    }

    /// One line for the UI.
    pub fn message(&self) -> String {
        match self {
            PasswordVerdict::Ok => "Strong enough.".to_owned(),
            PasswordVerdict::TooShort => format!("Use at least {MIN_PASSWORD_LEN} characters."),
            PasswordVerdict::ContainsUsername => {
                "Don't use your username in your password.".to_owned()
            }
            PasswordVerdict::Weak { hint } => hint.clone(),
        }
    }
}

/// Checks `password` for the account `username`.
pub fn check_password(username: &str, password: &str) -> PasswordVerdict {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return PasswordVerdict::TooShort;
    }
    let name = normalize_username(username);
    if !name.is_empty() && password.to_lowercase().contains(&name) {
        return PasswordVerdict::ContainsUsername;
    }
    let entropy = zxcvbn::zxcvbn(password, &[&name]);
    if u8::from(entropy.score()) >= MIN_SCORE {
        return PasswordVerdict::Ok;
    }
    let feedback = entropy.feedback();
    let warning = feedback.and_then(|f| f.warning()).map(|w| w.to_string());
    let suggestions = feedback.map(|f| {
        f.suggestions()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    });
    let hint = [warning, suggestions]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    PasswordVerdict::Weak {
        hint: if hint.is_empty() {
            "Add another word or two; uncommon words are best.".to_owned()
        } else {
            hint
        },
    }
}

/// The form of a username that unlocks: trimmed and lowercased, so
/// `Brendon` and ` brendon ` are the same account.
pub fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

/// Whether `username` can name an account: 1–32 characters after trimming,
/// none of them control characters.
pub fn valid_username(username: &str) -> bool {
    let name = username.trim();
    (1..=MAX_USERNAME_LEN).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_are_refused_with_a_reason() {
        assert_eq!(
            check_password("brendon", "abc123"),
            PasswordVerdict::TooShort
        );
        assert_eq!(
            check_password("brendon", "123456789"),
            PasswordVerdict::TooShort
        );
        assert_eq!(
            check_password("Brendon", "my-BRENDON-password-2026"),
            PasswordVerdict::ContainsUsername
        );
        for weak in ["password1234", "qwertyuiop", "iloveyou2026", "aaaaaaaaaaaa"] {
            match check_password("brendon", weak) {
                PasswordVerdict::Weak { hint } => assert!(!hint.is_empty(), "{weak}"),
                other => panic!("{weak}: {other:?}"),
            }
        }
    }

    #[test]
    fn strong_passwords_pass() {
        for strong in [
            "Tundra-Gravel-Mosaic-41",
            "copper lantern drifts sideways",
            "vR7#qL2!mZ9@wK",
        ] {
            assert_eq!(
                check_password("brendon", strong),
                PasswordVerdict::Ok,
                "{strong}"
            );
        }
        assert!(
            check_password("brendon", "Tundra-Gravel-Mosaic-41")
                .message()
                .contains("Strong")
        );
    }

    #[test]
    fn usernames_normalize_and_validate() {
        assert_eq!(normalize_username("  Brendon "), "brendon");
        assert_eq!(normalize_username("Brendon"), normalize_username("BRENDON"));
        assert!(valid_username("Brendon") && valid_username(" Strange ") && valid_username("ë"));
        assert!(!valid_username("") && !valid_username("   ") && !valid_username("a\nb"));
        assert!(valid_username(&"x".repeat(32)) && !valid_username(&"x".repeat(33)));
    }
}
