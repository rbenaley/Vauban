# Runbook -- MFA TOTP lockout smoke test

> Manual validation after shipping the login TOTP limiter, the per-user
> failure counter, and single-use TOTP windows (crates **0.9.48+**).
> CI covers the handler pyramid. Staging proves a real authenticator
> cannot be replayed and that a short burst of wrong codes locks the
> account the same way a bad password does.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** for the MFA lockout change. Do not ship without A-C.

Related:

- [IAM Architecture](../technical/Vauban_IAM_Architecture_EN(1.0).md)
- Handlers: `vauban-web/src/handlers/auth.rs` (`login`, `mfa_verify_submit`)

## Automated prerequisites

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy -p vauban-web --all-targets -- -D warnings
bash shared/scripts/check_security_claims.sh
rtk cargo test -p vauban-web -- mfa_rate_key consumed_totp off_window e2e_api_login e2e_web_login attack_repeated_totp attack_consumed_totp battle_concurrent_totp -- --test-threads=1
```

## A -- Wrong code then right code

1. Use an account with MFA enrolled and a known TOTP secret.
2. `POST /api/v1/auth/login` with the right password and a wrong 6-digit code.
3. Pass: HTTP 401, `failed_login_attempts` increased by one, account still usable.
4. Repeat the call with the current authenticator code.
5. Pass: HTTP 200 and a non-empty `access_token`. `failed_login_attempts` is 0.

## B -- Replay of the same window

1. Immediately repeat step A.4 with the same code and the same password.
2. Pass: HTTP 401. A code from the next 30-second window is accepted.

## C -- Lockout

1. Submit wrong codes until `failed_login_attempts` reaches `max_failed_login_attempts`.
2. Pass: the account is locked (`locked_until` in the future) and a following correct code is refused until the lock expires.
3. On the web form, a correct password followed by abandoning `/mfa/verify` leaves `failed_login_attempts` unchanged.
