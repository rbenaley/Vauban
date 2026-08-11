//! Contention: parallel `build_smtp_transport` for starttls/tls × cert flag.

use std::sync::{Arc, Barrier};
use std::thread;

use vcp::config::{MailConfig, SmtpEncryption};
use vcp::mailer::build_smtp_transport;

#[test]
fn battle_parallel_build_smtp_accept_invalid_matrix() {
    let cases = [
        (SmtpEncryption::Starttls, false, 587u16),
        (SmtpEncryption::Starttls, true, 587),
        (SmtpEncryption::Tls, false, 465),
        (SmtpEncryption::Tls, true, 465),
    ];
    let barrier = Arc::new(Barrier::new(cases.len()));
    let mut handles = Vec::new();
    for (enc, accept, port) in cases {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            barrier.wait();
            let cfg = MailConfig {
                smtp_host: "localhost".to_owned(),
                smtp_port: port,
                smtp_encryption: enc,
                smtp_username: String::new(),
                smtp_password: String::new(),
                smtp_accept_invalid_certs: accept,
                circuit_failure_threshold: 3,
                circuit_open_secs: 60,
            };
            rt.block_on(async {
                build_smtp_transport(&cfg).expect("build_smtp_transport");
            });
        }));
    }
    for h in handles {
        h.join().expect("thread join");
    }
}
