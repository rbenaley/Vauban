/// VAUBAN Web - Service Tests.
///
/// Integration tests for service-layer modules that need a real DB
/// connection but no live HTTP routing.
pub mod mailer_outbox_test;
pub mod recording_daily_cron_test;
pub mod recording_hydrator_test;
pub mod recording_reaper_test;
