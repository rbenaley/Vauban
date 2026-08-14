//! Sealed SMTP outbox drainer library surface.

pub mod broker;
pub mod db;
pub mod outbox;
pub mod provision;
pub mod smtp_client;

pub use provision::MailerRuntime;
