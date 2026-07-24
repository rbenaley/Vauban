//! RDP session management using IronRDP.
//!
//! Each session manages a full RDP connection lifecycle:
//! TCP connect -> TLS upgrade -> CredSSP/NLA -> active session.
//! Display updates are encoded as PNG regions and sent via IPC.

use crate::error::{SessionError, SessionResult};
use crate::rdp_recording_writer::RdpRecordingWriter;
use crate::session_manager::{RecordingLeaseClient, RecordingLeaseReq, RecordingWriteErrorHook};
use crate::video_encoder::VideoEncoder;
use base64::Engine as _;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};
use ironrdp::connector::{
    self, ClientConnector, ClientConnectorState, ConnectionResult, ConnectorError,
    ConnectorErrorKind, ConnectorResult, Credentials, DesktopSize, Sequence as _, Written,
    connection_activation::{ConnectionActivationFactory, ConnectionActivationState},
    sspi,
    sspi::credssp::{self as sspi_credssp, ClientState, CredSspClient, CredSspMode},
    sspi::generator::GeneratorState,
};
use ironrdp::core::WriteBuf;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::input::{self as rdp_input, Database as InputDatabase};
use ironrdp::pdu::PduHint;
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::geometry::Rectangle as _;
use ironrdp::pdu::input::fast_path::FastPathInputEvent;
use ironrdp::pdu::nego;
use ironrdp::pdu::rdp::capability_sets::{self, MajorPlatformType};
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::pdu::x224::X224;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStageBuilder, ActiveStageOutput, fast_path};
use ironrdp_tokio::single_sequence_step;
use ironrdp_tokio::{Framed, FramedRead, FramedWrite, NetworkClient, Upgraded};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use shared::messages::{Message, RdpAuthMode, RdpInputEvent};
use std::os::unix::io::{FromRawFd, IntoRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types;
use tracing::{debug, error, info, trace, warn};

/// Configuration for creating a new RDP session.
#[derive(Debug)]
pub struct SessionConfig {
    pub session_id: String,
    pub user_id: String,
    pub asset_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<SecretString>,
    pub domain: Option<String>,
    pub desktop_width: u16,
    pub desktop_height: u16,
    /// VAU-001: the pinned SHA-256 fingerprint of the target server's
    /// TLS `SubjectPublicKeyInfo` (format `SHA256:<base64>`), sourced from
    /// `assets.connection_config.rdp_server_cert_fingerprint`. The TLS
    /// handshake is refused (fail-closed) unless the live server SPKI
    /// matches this value. The session path NEVER carries an empty pin:
    /// `vauban-proxy-rdp::main` rejects `RdpSessionOpen` before building
    /// the `SessionConfig` when no pin was threaded.
    pub expected_cert_fingerprint: String,
    /// Pre-established TCP connection from supervisor (for sandboxed operation).
    /// When running in Capsicum sandbox, the proxy cannot open network connections.
    /// The supervisor establishes the TCP connection and passes the FD via SCM_RIGHTS.
    pub preconnected_fd: Option<OwnedFd>,
    /// NLA authentication mode for the CredSSP leg. `Ntlm` preserves the
    /// historical behavior; `KerberosRestrictedAdmin` sets the
    /// `RESTRICTED_ADMIN_MODE_REQUIRED` nego flag and drives CredSSP in
    /// credential-less mode (fail-closed: no NTLM fallback).
    pub auth_mode: RdpAuthMode,
    /// Supervisor KDC FD-lease handle (Kerberos mode only). `None` in NTLM
    /// mode or in non-sandboxed dev mode; Kerberos mode fails closed
    /// without it.
    pub supervisor_relay: Option<Arc<SupervisorRelay>>,
}

/// Active RDP session handle (the actual connection runs in a spawned task).
pub struct RdpSession {
    #[allow(dead_code)]
    pub session_id: String,
    #[allow(dead_code)]
    pub user_id: String,
    #[allow(dead_code)]
    pub asset_id: String,
    pub desktop_width: u16,
    pub desktop_height: u16,
    #[allow(dead_code)]
    pub created_at: Instant,
}

/// Commands that can be sent to an RDP session task.
#[derive(Debug)]
#[allow(dead_code)]
pub enum SessionCommand {
    Input(RdpInputEvent),
    Resize { width: u16, height: u16 },
    SetVideoMode { enabled: bool, bitrate_bps: u32 },
    Close,
}

impl RdpSession {
    /// Connect to an RDP server and spawn the active session loop.
    pub async fn connect(
        config: SessionConfig,
        web_tx: mpsc::Sender<Message>,
        cmd_rx: mpsc::Receiver<SessionCommand>,
        audit_tx: Option<mpsc::Sender<Message>>,
        recording_lease: Option<RecordingLeaseClient>,
        recording_write_error: Option<RecordingWriteErrorHook>,
    ) -> SessionResult<Self> {
        info!(
            session_id = %config.session_id,
            host = %config.host,
            port = config.port,
            username = %config.username,
            width = config.desktop_width,
            height = config.desktop_height,
            "Connecting to RDP server"
        );

        let password = config
            .password
            .as_ref()
            .map(|p| p.expose_secret().to_string())
            .unwrap_or_default();

        let connector_config = build_connector_config(
            config.username.clone(),
            password,
            config.domain.clone(),
            config.desktop_width,
            config.desktop_height,
        );

        // Connect to the RDP server - use pre-established FD if provided (sandboxed mode)
        // or open a new connection (non-sandboxed mode, e.g., development on macOS)
        let stream = if let Some(fd) = config.preconnected_fd {
            debug!(session_id = %config.session_id, "Using pre-established connection from supervisor");

            // SAFETY: The FD comes from the supervisor via SCM_RIGHTS and is a valid TCP socket
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd.into_raw_fd()) };
            std_stream.set_nonblocking(true).map_err(|e| {
                SessionError::ConnectionFailed(format!("Failed to set non-blocking: {e}"))
            })?;
            TcpStream::from_std(std_stream).map_err(|e| {
                SessionError::ConnectionFailed(format!("Failed to create tokio stream: {e}"))
            })?
        } else {
            // Non-sandboxed mode: resolve DNS and open connection directly (development/macOS)
            let addr_str = format!("{}:{}", config.host, config.port);
            let server_addr = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::lookup_host(&addr_str),
            )
            .await
            .map_err(|_| SessionError::ConnectionFailed("DNS resolution timed out".to_string()))?
            .map_err(|e| SessionError::ConnectionFailed(format!("DNS resolution failed: {e}")))?
            .next()
            .ok_or_else(|| SessionError::ConnectionFailed("No addresses resolved".to_string()))?;

            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                TcpStream::connect(server_addr),
            )
            .await
            .map_err(|_| {
                SessionError::ConnectionFailed(format!(
                    "TCP connect to {}:{} timed out after 10s",
                    config.host, config.port
                ))
            })?
            .map_err(|e| SessionError::ConnectionFailed(format!("TCP connect failed: {e}")))?
        };

        let server_addr = stream
            .peer_addr()
            .map_err(|e| SessionError::ConnectionFailed(format!("peer addr: {e}")))?;
        let client_addr = stream
            .local_addr()
            .map_err(|e| SessionError::ConnectionFailed(format!("local addr: {e}")))?;

        trace!(session_id = %config.session_id, %server_addr, "TCP connection established");

        let drdynvc =
            DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|caps| {
                trace!("Display Control capabilities: {:?}", caps);
                Ok(Vec::new())
            }));
        let mut connector =
            ClientConnector::new(connector_config, client_addr).with_static_channel(drdynvc);

        // Wrap in IronRDP framing
        let mut framed = ironrdp_tokio::TokioFramed::new(stream);

        // Drive connection up to TLS upgrade point. Local mirror of
        // `ironrdp_tokio::connect_begin`: in Kerberos / Restricted Admin
        // mode the X.224 Connection Request must carry the
        // RESTRICTED_ADMIN_MODE_REQUIRED nego flag, which upstream
        // hardcodes to empty.
        let extra_nego_flags = match config.auth_mode {
            RdpAuthMode::Ntlm => nego::RequestFlags::empty(),
            RdpAuthMode::KerberosRestrictedAdmin => {
                nego::RequestFlags::RESTRICTED_ADMIN_MODE_REQUIRED
            }
        };
        let should_upgrade =
            connect_begin_with_nego_flags(&mut framed, &mut connector, extra_nego_flags)
                .await
                .map_err(|e| {
                    SessionError::ConnectionFailed(format!("RDP handshake begin failed: {e}"))
                })?;

        trace!(session_id = %config.session_id, "TLS upgrade starting");

        // Perform TLS upgrade
        let server_name: pki_types::ServerName<'static> = config
            .host
            .clone()
            .try_into()
            .unwrap_or_else(|_| pki_types::ServerName::IpAddress(server_addr.ip().into()));

        // VAU-001: pin the target server's TLS SPKI. The verifier refuses
        // the handshake (fail-closed) on mismatch, BEFORE the server public
        // key is extracted below for CredSSP channel binding -- so CredSSP
        // never binds to an unverified key.
        let tls_config = build_tls_config(&config.expected_cert_fingerprint)?;
        let tls_connector = tokio_rustls::TlsConnector::from(tls_config);

        let tcp_stream = framed.into_inner_no_leftover();
        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tls_connector.connect(server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|_| {
            SessionError::TlsUpgradeFailed("TLS handshake timed out after 10s".to_string())
        })?
        .map_err(|e| SessionError::TlsUpgradeFailed(e.to_string()))?;

        trace!(session_id = %config.session_id, "TLS upgrade complete");

        // Extract server public key for CredSSP
        let (_, client_connection) = tls_stream.get_ref();
        let server_public_key = client_connection
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| extract_tls_server_public_key(cert))
            .transpose()
            .map_err(|e| {
                SessionError::TlsUpgradeFailed(format!("Failed to extract server public key: {e}"))
            })?
            .unwrap_or_default();

        let mut tls_framed = ironrdp_tokio::TokioFramed::new(tls_stream);

        let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

        // Finalize connection (CredSSP + remaining handshake). The local
        // demuxed loop (NOT ironrdp_tokio::connect_finalize) shields the
        // licensing exchange from interleaved message-channel PDUs.
        // NTLM keeps the network-less NtlmOnlyNetworkClient; Kerberos mode
        // relays KDC exchanges to the supervisor (fail-closed without the
        // relay handle).
        let mut network_client = SessionNetworkClient::for_auth_mode(
            config.auth_mode,
            config.supervisor_relay.clone(),
            &config.session_id,
        )?;
        let connection_result = connect_finalize_with_message_channel_demux(
            upgraded,
            connector,
            &mut tls_framed,
            &mut network_client,
            connector::ServerName::new(config.host.clone()),
            server_public_key,
            config.auth_mode,
        )
        .await
        .map_err(|e| SessionError::AuthenticationFailed(format!("RDP finalize failed: {e}")))?;

        let actual_width = connection_result.desktop_size.width;
        let actual_height = connection_result.desktop_size.height;

        info!(
            session_id = %config.session_id,
            width = actual_width,
            height = actual_height,
            "RDP session connected"
        );

        let session = Self {
            session_id: config.session_id.clone(),
            user_id: config.user_id.clone(),
            asset_id: config.asset_id.clone(),
            desktop_width: actual_width,
            desktop_height: actual_height,
            created_at: Instant::now(),
        };

        // Spawn the active session processing loop
        let session_id = config.session_id.clone();
        tokio::spawn(async move {
            if let Err(e) = active_session_loop(
                session_id.clone(),
                connection_result,
                tls_framed,
                web_tx,
                cmd_rx,
                SessionRecording {
                    audit_tx,
                    lease: recording_lease,
                    write_error: recording_write_error,
                },
            )
            .await
            {
                error!(session_id = %session_id, error = %e, "RDP session loop error");
            }
        });

        Ok(session)
    }
}

fn build_connector_config(
    username: String,
    password: String,
    domain: Option<String>,
    width: u16,
    height: u16,
) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword { username, password },
        domain,
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0x0409,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize { width, height },
        bitmap: Some(connector::BitmapConfig {
            lossy_compression: true,
            color_depth: 32,
            codecs: capability_sets::client_codecs_capabilities(&[])
                .unwrap_or_else(|_| capability_sets::BitmapCodecs(Vec::new())),
        }),
        client_build: 0,
        client_name: "Vauban".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        // No startup program / working directory override on the target.
        alternate_shell: String::new(),
        work_dir: String::new(),
        // Conservative posture, identical to the pre-0.17 behavior: no
        // bulk compression and no UDP sideband transport negotiation.
        compression_type: None,
        multitransport_flags: None,

        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(target_os = "linux")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "freebsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(not(any(
            windows,
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd"
        )))]
        platform: MajorPlatformType::UNSPECIFIED,

        enable_server_pointer: false,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        pointer_software_rendering: true,
        performance_flags: PerformanceFlags::DISABLE_WALLPAPER
            | PerformanceFlags::DISABLE_THEMING
            | PerformanceFlags::DISABLE_CURSOR_SHADOW
            | PerformanceFlags::DISABLE_CURSORSETTINGS
            | PerformanceFlags::DISABLE_FULLWINDOWDRAG
            | PerformanceFlags::DISABLE_MENUANIMATIONS,
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
    }
}

/// Round a dimension up to the nearest even number (H.264 YUV 4:2:0 requirement).
/// Round up to the nearest even value (H.264 YUV 4:2:0 requires even
/// dimensions). Total on all of `u16`: `u16::MAX` clamps DOWN to `65534`
/// instead of overflowing (the server controls these values, a hostile
/// peer must not be able to panic the session task).
fn align_even(v: u16) -> u16 {
    if v.is_multiple_of(2) {
        v
    } else {
        v.saturating_add(1) & !1
    }
}

/// Commands sent to the background encoder thread.
enum EncoderCommand {
    /// Encode a framebuffer snapshot (RGBA data, width, height).
    Encode(Vec<u8>, u16, u16),
    /// Reconfigure encoder for new dimensions.
    Reconfigure(u16, u16),
    /// Force next frame to be a keyframe.
    ForceKeyframe,
}

/// Spawns a background thread that encodes H.264 frames without blocking async I/O.
fn spawn_encoder_thread(
    width: u16,
    height: u16,
    bitrate_bps: u32,
    mut cmd_rx: mpsc::Receiver<EncoderCommand>,
    result_tx: mpsc::Sender<(crate::video_encoder::VideoFrame, u64)>,
    session_id: String,
) {
    std::thread::spawn(move || {
        let width = align_even(width);
        let height = align_even(height);
        let encoder_result = if bitrate_bps > 0 {
            VideoEncoder::new(width, height, bitrate_bps)
        } else {
            VideoEncoder::with_defaults(width, height)
        };
        let mut encoder = match encoder_result {
            Ok(enc) => enc,
            Err(e) => {
                error!(session_id = %session_id, error = %e, "Encoder thread: failed to create encoder");
                return;
            }
        };
        info!(session_id = %session_id, "H.264 encoder thread started");

        while let Some(cmd) = cmd_rx.blocking_recv() {
            match cmd {
                EncoderCommand::Encode(mut rgba_data, w, h) => {
                    let aw = align_even(w);
                    let ah = align_even(h);
                    if (aw != encoder.dimensions().0 || ah != encoder.dimensions().1)
                        && let Err(e) = encoder.reconfigure(aw, ah)
                    {
                        warn!(session_id = %session_id, error = %e, "Encoder thread: reconfigure failed");
                        continue;
                    }
                    let expected = usize::from(aw) * usize::from(ah) * 4;
                    if rgba_data.len() < expected {
                        rgba_data.resize(expected, 0);
                    }
                    let encode_start = Instant::now();
                    match encoder.encode_frame(&rgba_data) {
                        Ok(frame) => {
                            let elapsed_us = encode_start.elapsed().as_micros() as u64;
                            if result_tx.blocking_send((frame, elapsed_us)).is_err() {
                                debug!(session_id = %session_id, "Encoder thread: result channel closed");
                                return;
                            }
                        }
                        Err(e) => {
                            warn!(session_id = %session_id, error = %e, "Encoder thread: encode failed");
                        }
                    }
                }
                EncoderCommand::Reconfigure(w, h) => {
                    let w = align_even(w);
                    let h = align_even(h);
                    if let Err(e) = encoder.reconfigure(w, h) {
                        warn!(session_id = %session_id, error = %e, "Encoder thread: reconfigure failed");
                    }
                }
                EncoderCommand::ForceKeyframe => {
                    encoder.force_keyframe();
                }
            }
        }
        info!(session_id = %session_id, "H.264 encoder thread exited");
    });
}

struct SessionRecording {
    audit_tx: Option<mpsc::Sender<Message>>,
    lease: Option<RecordingLeaseClient>,
    write_error: Option<RecordingWriteErrorHook>,
}

/// Main processing loop for an active RDP session.
async fn active_session_loop(
    session_id: String,
    connection_result: ConnectionResult,
    mut framed: ironrdp_tokio::TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>,
    web_tx: mpsc::Sender<Message>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    recording: SessionRecording,
) -> SessionResult<()> {
    let SessionRecording {
        audit_tx,
        lease: recording_lease,
        write_error: recording_write_error,
    } = recording;
    let desktop_w = connection_result.desktop_size.width;
    let desktop_h = connection_result.desktop_size.height;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop_w, desktop_h);
    // Retained to drive the Deactivation-Reactivation Sequence locally
    // (since IronRDP 0.17, ActiveStageOutput::DeactivateAll is a unit
    // variant and the consumer produces fresh activation sequences).
    let activation_factory = connection_result.activation_factory;
    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
    }
    .build();
    let mut input_db = InputDatabase::new();
    let mut lock_sync = LockSyncState::default();
    let mut graphics_update_count: u64 = 0;
    let mut _response_frame_count: u64 = 0;
    let mut pdu_count: u64 = 0;

    let mut video_mode = false;
    let framebuffer_dirty = Arc::new(AtomicBool::new(false));
    let mut encode_interval = interval(std::time::Duration::from_millis(16)); // 60 FPS max
    let mut suppress_encoding_until: Option<Instant> = None;

    // Channel for receiving encoded H.264 frames from the encoder thread
    let (encoded_tx, mut encoded_rx) = mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(4);
    // Channel for sending framebuffer snapshots to the encoder thread
    let mut encoder_snapshot_tx: Option<mpsc::Sender<EncoderCommand>> = None;

    // Performance metrics: log every 5 seconds
    let mut perf_interval = interval(std::time::Duration::from_secs(5));
    let mut recording_sync_interval = interval(std::time::Duration::from_secs(1));
    recording_sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut perf_gfx_updates: u64 = 0;
    let mut perf_encoded_frames: u64 = 0;
    let mut perf_dirty_skips: u64 = 0;
    let mut perf_encode_time_us: u64 = 0;

    trace!(session_id = %session_id, "Active session loop started");

    let mut recording_loss_observed = false;
    let mut recording_writer = if let Some(ref lease) = recording_lease {
        let relative_path = RdpRecordingWriter::first_segment_path(&session_id);
        match lease_recording_file(lease, &session_id, &relative_path).await {
            Ok(file) => Some(RdpRecordingWriter::new(file, relative_path)),
            Err(error) => {
                observe_recording_error(
                    &session_id,
                    &error,
                    &recording_write_error,
                    &web_tx,
                    &mut recording_loss_observed,
                );
                None
            }
        }
    } else {
        None
    };

    if recording_writer.is_some()
        && let Some(ref tx) = audit_tx
    {
        let _ = tx
            .send(Message::RdpRecordingStart {
                session_id: session_id.clone(),
                width: align_even(desktop_w),
                height: align_even(desktop_h),
            })
            .await;
        debug!(session_id = %session_id, "Sent RdpRecordingStart to audit");
    }

    let recording_result: SessionResult<()> = async {
    loop {
        tokio::select! {
            _ = recording_sync_interval.tick(), if recording_writer.is_some() => {
                let sync_error = recording_writer
                    .as_mut()
                    .and_then(|writer| writer.sync_if_dirty().err());
                if let Some(error) = sync_error {
                    observe_recording_error(
                        &session_id,
                        &error,
                        &recording_write_error,
                        &web_tx,
                        &mut recording_loss_observed,
                    );
                    recording_writer = None;
                }
            }

            // Read and process PDU from RDP server
            frame_result = framed.read_pdu() => {
                let (action, payload) = frame_result.map_err(|e| {
                    SessionError::SessionFailed(format!("Read PDU error: {e}"))
                })?;

                pdu_count += 1;
                if pdu_count <= 20 || pdu_count.is_multiple_of(100) {
                    trace!(
                        session_id = %session_id,
                        pdu_count,
                        action = ?action,
                        payload_len = payload.len(),
                        "PDU received"
                    );
                }

                let outputs = active_stage.process(&mut image, action, &payload)
                    .map_err(|e| SessionError::SessionFailed(format!("Process error: {e}")))?;

                for output in &outputs {
                    match output {
                        ActiveStageOutput::GraphicsUpdate(region) => {
                            trace!(
                                session_id = %session_id,
                                x = region.left, y = region.top,
                                w = region.width(), h = region.height(),
                                graphics_update_count,
                                "GraphicsUpdate region"
                            );
                        }
                        ActiveStageOutput::DeactivateAll => {
                            info!(session_id = %session_id, "DeactivateAll received");
                        }
                        ActiveStageOutput::Terminate(reason) => {
                            info!(session_id = %session_id, ?reason, "Terminate received");
                        }
                        ActiveStageOutput::ResponseFrame(frame) => {
                            trace!(
                                session_id = %session_id,
                                frame_len = frame.len(),
                                "ResponseFrame to send"
                            );
                        }
                        other => {
                            trace!(session_id = %session_id, output = ?std::mem::discriminant(other), "Other output");
                        }
                    }
                }

                for output in outputs {
                    match output {
                        ActiveStageOutput::ResponseFrame(frame) => {
                            _response_frame_count += 1;
                            framed.write_all(&frame)
                                .await
                                .map_err(|e| SessionError::SessionFailed(format!("Write error: {e}")))?;
                        }
                        ActiveStageOutput::GraphicsUpdate(region) => {
                            graphics_update_count += 1;

                            if video_mode {
                                framebuffer_dirty.store(true, Ordering::Relaxed);
                                perf_gfx_updates += 1;
                            } else {
                                let x = region.left;
                                let y = region.top;
                                let w = region.width();
                                let h = region.height();

                                match encode_region_as_png(&image, x, y, w, h) {
                                    Ok(png_data) => {
                                        if graphics_update_count <= 20 || graphics_update_count.is_multiple_of(50) {
                                            trace!(
                                                session_id = %session_id,
                                                graphics_update_count,
                                                x, y, w, h,
                                                png_bytes = png_data.len(),
                                                "Sending display update (PNG)"
                                            );
                                        }
                                        let msg = Message::RdpDisplayUpdate {
                                            session_id: session_id.clone(),
                                            x, y,
                                            width: w,
                                            height: h,
                                            png_data,
                                        };
                                        if web_tx.send(msg).await.is_err() {
                                            warn!(session_id = %session_id, "Web channel closed");
                                            return Ok(());
                                        }
                                    }
                                    Err(e) => {
                                        warn!(session_id = %session_id, error = %e, x, y, w, h, "PNG encoding failed, skipping update");
                                    }
                                }
                            }
                        }
                        ActiveStageOutput::Terminate(reason) => {
                            info!(session_id = %session_id, ?reason, "RDP server terminated session");
                            return Ok(());
                        }
                        ActiveStageOutput::DeactivateAll => {
                            debug!(session_id = %session_id, "Deactivation-Reactivation Sequence started");
                            let outcome = drive_reactivation(&activation_factory, &mut framed)
                                .await
                                .map_err(|e| SessionError::SessionFailed(
                                    format!("Deactivation-Reactivation failed: {e}")
                                ))?;
                            let desktop_size = outcome.desktop_size;
                            debug!(
                                session_id = %session_id,
                                ?desktop_size,
                                "Deactivation-Reactivation Sequence completed"
                            );
                            image = DecodedImage::new(
                                PixelFormat::RgbA32,
                                desktop_size.width,
                                desktop_size.height,
                            );
                            active_stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: outcome.io_channel_id,
                                    user_channel_id: outcome.user_channel_id,
                                    share_id: outcome.share_id,
                                    enable_server_pointer: outcome.enable_server_pointer,
                                    pointer_software_rendering: outcome.pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            active_stage.set_share_id(outcome.share_id);
                            active_stage.set_enable_server_pointer(outcome.enable_server_pointer);

                            let aligned_w = align_even(desktop_size.width);
                            let aligned_h = align_even(desktop_size.height);

                            if let Some(ref tx) = encoder_snapshot_tx {
                                let _ = tx.try_send(EncoderCommand::Reconfigure(
                                    aligned_w,
                                    aligned_h,
                                ));
                                suppress_encoding_until = Some(
                                    Instant::now() + std::time::Duration::from_millis(500)
                                );
                            }

                            let _ = web_tx.send(Message::RdpDesktopResize {
                                session_id: session_id.clone(),
                                width: aligned_w,
                                height: aligned_h,
                            }).await;
                            info!(
                                session_id = %session_id,
                                width = desktop_size.width,
                                height = desktop_size.height,
                                "Desktop resized after reactivation"
                            );
                        }
                        _ => {}
                    }
                }
            }

            // Handle commands from web
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SessionCommand::Input(input_event)) => {
                        let fastpath_events =
                            handle_input_event(&mut input_db, &mut lock_sync, input_event);

                        if !fastpath_events.is_empty() {
                            let outputs = active_stage
                                .process_fastpath_input(&mut image, &fastpath_events)
                                .map_err(|e| SessionError::SessionFailed(format!("Input error: {e}")))?;

                            for output in outputs {
                                if let ActiveStageOutput::ResponseFrame(frame) = output {
                                    framed.write_all(&frame)
                                        .await
                                        .map_err(|e| SessionError::SessionFailed(format!("Write error: {e}")))?;
                                }
                            }
                        }
                    }
                    Some(SessionCommand::Resize { width, height }) => {
                        let w = width.max(200) & !1;
                        let h = height.max(200) & !1;
                        info!(session_id = %session_id, width = w, height = h, "Resize requested");

                        match active_stage.encode_resize(u32::from(w), u32::from(h), None, None) {
                            Some(Ok(frame)) => {
                                if !frame.is_empty() {
                                    framed.write_all(&frame)
                                        .await
                                        .map_err(|e| SessionError::SessionFailed(format!("Resize write error: {e}")))?;
                                }
                                debug!(session_id = %session_id, w, h, "Resize sent via Display Control channel");
                            }
                            Some(Err(e)) => {
                                warn!(session_id = %session_id, error = %e, "Failed to encode resize");
                            }
                            None => {
                                debug!(session_id = %session_id, "Display Control channel not available for resize");
                            }
                        }
                    }
                    Some(SessionCommand::SetVideoMode { enabled, bitrate_bps }) => {
                        info!(session_id = %session_id, enabled, bitrate_bps, "Video mode toggled");
                        video_mode = enabled;
                        if enabled && encoder_snapshot_tx.is_none() {
                            let (snap_tx, snap_rx) = mpsc::channel::<EncoderCommand>(2);
                            spawn_encoder_thread(
                                image.width(),
                                image.height(),
                                bitrate_bps,
                                snap_rx,
                                encoded_tx.clone(),
                                session_id.clone(),
                            );
                            encoder_snapshot_tx = Some(snap_tx);
                            framebuffer_dirty.store(true, Ordering::Relaxed);
                            info!(session_id = %session_id, "H.264 encoder thread spawned");
                        }
                    }
                    Some(SessionCommand::Close) => {
                        info!(session_id = %session_id, "Close requested");
                        return Ok(());
                    }
                    None => {
                        debug!(session_id = %session_id, "Command channel closed");
                        return Ok(());
                    }
                }
            }

            // Performance metrics reporting (every 5 seconds)
            _ = perf_interval.tick(), if video_mode => {
                if perf_gfx_updates > 0 || perf_encoded_frames > 0 {
                    let avg_encode_ms = perf_encode_time_us
                        .checked_div(perf_encoded_frames)
                        .map(|us_per_frame| us_per_frame / 1000)
                        .unwrap_or(0);
                    info!(
                        session_id = %session_id,
                        gfx_updates_5s = perf_gfx_updates,
                        encoded_frames_5s = perf_encoded_frames,
                        dirty_skips_5s = perf_dirty_skips,
                        avg_encode_ms,
                        gfx_fps = perf_gfx_updates / 5,
                        encode_fps = perf_encoded_frames / 5,
                        "H.264 perf metrics"
                    );
                }
                perf_gfx_updates = 0;
                perf_encoded_frames = 0;
                perf_dirty_skips = 0;
                perf_encode_time_us = 0;
            }

            // H.264 encoding tick: snapshot framebuffer and send to encoder thread
            _ = encode_interval.tick(), if video_mode => {
                if let Some(until) = suppress_encoding_until {
                    if Instant::now() < until {
                        continue;
                    }
                    suppress_encoding_until = None;
                    if let Some(ref tx) = encoder_snapshot_tx {
                        let _ = tx.try_send(EncoderCommand::ForceKeyframe);
                    }
                    debug!(session_id = %session_id, "Post-resize grace period ended, resuming encoding");
                }
                if !framebuffer_dirty.swap(false, Ordering::Relaxed) {
                    perf_dirty_skips += 1;
                    continue;
                }
                if let Some(ref tx) = encoder_snapshot_tx {
                    let snapshot = image.data().to_vec();
                    let w = image.width();
                    let h = image.height();
                    if tx.try_send(EncoderCommand::Encode(snapshot, w, h)).is_err() {
                        trace!(session_id = %session_id, "Encoder busy, skipping frame");
                        perf_dirty_skips += 1;
                        framebuffer_dirty.store(true, Ordering::Relaxed);
                    }
                }
            }

            // Receive encoded H.264 frames from encoder thread
            Some((frame, encode_elapsed_us)) = encoded_rx.recv() => {
                perf_encoded_frames += 1;
                perf_encode_time_us += encode_elapsed_us;

                let segment_needed = match recording_writer.as_mut() {
                    Some(writer) => writer.handle_frame(
                        frame.timestamp_us,
                        frame.is_keyframe,
                        frame.width,
                        frame.height,
                        &frame.data,
                    ),
                    None => Ok(None),
                };
                match segment_needed {
                    Ok(Some(segment)) => {
                        if let Some(ref lease) = recording_lease {
                            match lease_recording_file(lease, &session_id, &segment.relative_path).await {
                                Ok(file) => {
                                    if let Some(writer) = recording_writer.as_mut()
                                        && let Err(error) = writer.provide_segment_file(file)
                                    {
                                        observe_recording_error(
                                            &session_id,
                                            &error,
                                            &recording_write_error,
                                            &web_tx,
                                            &mut recording_loss_observed,
                                        );
                                        recording_writer = None;
                                    }
                                }
                                Err(error) => {
                                    observe_recording_error(
                                        &session_id,
                                        &error,
                                        &recording_write_error,
                                        &web_tx,
                                        &mut recording_loss_observed,
                                    );
                                    recording_writer = None;
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        observe_recording_error(
                            &session_id,
                            &error,
                            &recording_write_error,
                            &web_tx,
                            &mut recording_loss_observed,
                        );
                        recording_writer = None;
                    }
                }

                let msg = Message::RdpVideoFrame {
                    session_id: session_id.clone(),
                    timestamp_us: frame.timestamp_us,
                    is_keyframe: frame.is_keyframe,
                    width: frame.width,
                    height: frame.height,
                    data: frame.data,
                };
                if web_tx.send(msg).await.is_err() {
                    warn!(session_id = %session_id, "Web channel closed");
                    return Ok(());
                }
            }
        }
    }
    }.await;

    if let Some(writer) = recording_writer {
        match writer.finish() {
            Ok(Some(seal)) => {
                if let Some(ref tx) = audit_tx {
                    let _ = tx
                        .send(Message::RdpRecordingEnd {
                            session_id: session_id.clone(),
                            segments: seal.segments,
                            meta_json_relative_path: seal.meta_json_relative_path,
                            total_frames: seal.total_frames,
                            total_bytes: seal.total_bytes,
                        })
                        .await;
                    debug!(session_id = %session_id, "Sent sealed RdpRecordingEnd to audit");
                }
            }
            Ok(None) => {}
            Err(error) => observe_recording_error(
                &session_id,
                &error,
                &recording_write_error,
                &web_tx,
                &mut recording_loss_observed,
            ),
        }
    }

    recording_result
}

async fn lease_recording_file(
    client: &RecordingLeaseClient,
    session_id: &str,
    relative_path: &str,
) -> Result<std::fs::File, String> {
    let (reply, receive) = tokio::sync::oneshot::channel();
    client
        .tx
        .send(RecordingLeaseReq {
            session_id: session_id.to_string(),
            relative_path: relative_path.to_string(),
            reply,
        })
        .await
        .map_err(|_| "recording lease channel closed".to_string())?;
    match tokio::time::timeout(shared::recording_fd::DEFAULT_BROKER_TIMEOUT, receive).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("recording lease reply channel closed".to_string()),
        Err(_) => Err("recording lease timed out".to_string()),
    }
}

fn observe_recording_error(
    session_id: &str,
    error: &dyn std::fmt::Display,
    hook: &Option<RecordingWriteErrorHook>,
    web_tx: &mpsc::Sender<Message>,
    loss_observed: &mut bool,
) {
    if *loss_observed {
        return;
    }
    *loss_observed = true;
    error!(session_id = %session_id, error = %error, "RDP recording write failed");
    if let Some(hook) = hook {
        hook(session_id);
    }
    if web_tx
        .try_send(Message::RecordingLossObserved {
            session_id: session_id.to_string(),
        })
        .is_err()
    {
        warn!(session_id = %session_id, "Failed to enqueue RecordingLossObserved to web");
    }
}

/// Last lock-key state synchronized to the RDP server.
///
/// The browser reports CapsLock/NumLock/ScrollLock on every keydown
/// (`KeyboardEvent.getModifierState`); an RDP Synchronize Event is emitted
/// only when that state drifts from the last one sent, so the server-side
/// lock state converges without flooding the wire.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LockSyncState {
    synced: Option<(bool, bool, bool)>,
}

impl LockSyncState {
    /// Returns a Synchronize Event iff the reported lock state differs
    /// from the last synchronized one (always fires on the first report).
    fn reconcile(
        &mut self,
        caps_lock: bool,
        num_lock: bool,
        scroll_lock: bool,
    ) -> Option<FastPathInputEvent> {
        let current = (caps_lock, num_lock, scroll_lock);
        if self.synced == Some(current) {
            return None;
        }
        self.synced = Some(current);
        // kana_lock is not reported by browsers; always false.
        Some(rdp_input::synchronize_event(
            scroll_lock,
            num_lock,
            caps_lock,
            false,
        ))
    }
}

/// Convert one web-originated input event into the FastPath events to send.
///
/// - `ReleaseAll` releases every key/button tracked by `input_db`
///   (stuck-modifier fix: fired on browser focus loss / WS reconnect);
/// - `Keyboard` prepends a Synchronize Event when the browser-reported
///   lock-key state drifted (see [`LockSyncState`]);
/// - everything else goes through [`translate_input_event`] unchanged.
fn handle_input_event(
    input_db: &mut InputDatabase,
    lock_sync: &mut LockSyncState,
    event: RdpInputEvent,
) -> Vec<FastPathInputEvent> {
    if matches!(event, RdpInputEvent::ReleaseAll) {
        return input_db.release_all().into_iter().collect();
    }

    let mut events: Vec<FastPathInputEvent> = Vec::new();
    if let RdpInputEvent::Keyboard {
        caps_lock,
        num_lock,
        scroll_lock,
        ..
    } = &event
        && let Some(sync) = lock_sync.reconcile(*caps_lock, *num_lock, *scroll_lock)
    {
        events.push(sync);
    }
    events.extend(input_db.apply(translate_input_event(event)));
    events
}

fn translate_input_event(event: RdpInputEvent) -> Vec<rdp_input::Operation> {
    match event {
        RdpInputEvent::KeyPressed { scancode } => {
            let (extended, code) = split_scancode(scancode);
            vec![rdp_input::Operation::KeyPressed(
                rdp_input::Scancode::from_u8(extended, code),
            )]
        }
        RdpInputEvent::KeyReleased { scancode } => {
            let (extended, code) = split_scancode(scancode);
            vec![rdp_input::Operation::KeyReleased(
                rdp_input::Scancode::from_u8(extended, code),
            )]
        }
        RdpInputEvent::MouseMove { x, y } => {
            vec![rdp_input::Operation::MouseMove(rdp_input::MousePosition {
                x,
                y,
            })]
        }
        RdpInputEvent::MouseButtonPressed { button } => {
            let Some(btn) = map_mouse_button(button) else {
                return vec![];
            };
            vec![rdp_input::Operation::MouseButtonPressed(btn)]
        }
        RdpInputEvent::MouseButtonReleased { button } => {
            let Some(btn) = map_mouse_button(button) else {
                return vec![];
            };
            vec![rdp_input::Operation::MouseButtonReleased(btn)]
        }
        RdpInputEvent::WheelScroll { vertical, amount } => {
            vec![rdp_input::Operation::WheelRotations(
                rdp_input::WheelRotations {
                    is_vertical: vertical,
                    rotation_units: amount,
                },
            )]
        }

        // High-level variants from web frontend
        RdpInputEvent::MouseButton {
            button,
            pressed,
            x,
            y,
        } => {
            let Some(btn) = map_mouse_button(button) else {
                return vec![];
            };
            let mut ops = vec![rdp_input::Operation::MouseMove(rdp_input::MousePosition {
                x,
                y,
            })];
            if pressed {
                ops.push(rdp_input::Operation::MouseButtonPressed(btn));
            } else {
                ops.push(rdp_input::Operation::MouseButtonReleased(btn));
            }
            ops
        }
        RdpInputEvent::MouseWheel { delta_x, delta_y } => {
            let mut ops = Vec::new();
            if delta_y != 0 {
                ops.push(rdp_input::Operation::WheelRotations(
                    rdp_input::WheelRotations {
                        is_vertical: true,
                        // Browser delta is inverted. Saturating: a raw
                        // `-` panics on i16::MIN in debug builds.
                        rotation_units: delta_y.saturating_neg(),
                    },
                ));
            }
            if delta_x != 0 {
                ops.push(rdp_input::Operation::WheelRotations(
                    rdp_input::WheelRotations {
                        is_vertical: false,
                        rotation_units: delta_x,
                    },
                ));
            }
            ops
        }
        RdpInputEvent::Keyboard { code, pressed, .. } => {
            let scancode = js_code_to_scancode(&code);
            if scancode == 0 {
                return vec![];
            }
            let (extended, sc) = split_scancode(scancode);
            if pressed {
                vec![rdp_input::Operation::KeyPressed(
                    rdp_input::Scancode::from_u8(extended, sc),
                )]
            } else {
                vec![rdp_input::Operation::KeyReleased(
                    rdp_input::Scancode::from_u8(extended, sc),
                )]
            }
        }

        // Handled by handle_input_event before translation (release_all is
        // an InputDatabase method, not an Operation); kept for exhaustiveness.
        RdpInputEvent::ReleaseAll => vec![],
    }
}

#[allow(clippy::cast_possible_truncation)]
fn split_scancode(scancode: u16) -> (bool, u8) {
    if scancode > 0xFF {
        (true, (scancode & 0xFF) as u8)
    } else {
        (false, scancode as u8)
    }
}

fn map_mouse_button(button: u8) -> Option<rdp_input::MouseButton> {
    match button {
        0 => Some(rdp_input::MouseButton::Left),
        1 => Some(rdp_input::MouseButton::Middle),
        2 => Some(rdp_input::MouseButton::Right),
        3 => Some(rdp_input::MouseButton::X1),
        4 => Some(rdp_input::MouseButton::X2),
        _ => None,
    }
}

/// Map JavaScript `KeyboardEvent.code` values to PS/2 Set 1 scancodes.
/// Extended keys use 0xE0xx encoding.
fn js_code_to_scancode(code: &str) -> u16 {
    match code {
        "Escape" => 0x01,
        "Digit1" => 0x02,
        "Digit2" => 0x03,
        "Digit3" => 0x04,
        "Digit4" => 0x05,
        "Digit5" => 0x06,
        "Digit6" => 0x07,
        "Digit7" => 0x08,
        "Digit8" => 0x09,
        "Digit9" => 0x0A,
        "Digit0" => 0x0B,
        "Minus" => 0x0C,
        "Equal" => 0x0D,
        "Backspace" => 0x0E,
        "Tab" => 0x0F,
        "KeyQ" => 0x10,
        "KeyW" => 0x11,
        "KeyE" => 0x12,
        "KeyR" => 0x13,
        "KeyT" => 0x14,
        "KeyY" => 0x15,
        "KeyU" => 0x16,
        "KeyI" => 0x17,
        "KeyO" => 0x18,
        "KeyP" => 0x19,
        "BracketLeft" => 0x1A,
        "BracketRight" => 0x1B,
        "Enter" => 0x1C,
        "ControlLeft" => 0x1D,
        "KeyA" => 0x1E,
        "KeyS" => 0x1F,
        "KeyD" => 0x20,
        "KeyF" => 0x21,
        "KeyG" => 0x22,
        "KeyH" => 0x23,
        "KeyJ" => 0x24,
        "KeyK" => 0x25,
        "KeyL" => 0x26,
        "Semicolon" => 0x27,
        "Quote" => 0x28,
        "Backquote" => 0x29,
        "ShiftLeft" => 0x2A,
        "Backslash" => 0x2B,
        "KeyZ" => 0x2C,
        "KeyX" => 0x2D,
        "KeyC" => 0x2E,
        "KeyV" => 0x2F,
        "KeyB" => 0x30,
        "KeyN" => 0x31,
        "KeyM" => 0x32,
        "Comma" => 0x33,
        "Period" => 0x34,
        "Slash" => 0x35,
        "ShiftRight" => 0x36,
        "NumpadMultiply" => 0x37,
        "AltLeft" => 0x38,
        "Space" => 0x39,
        "CapsLock" => 0x3A,
        "F1" => 0x3B,
        "F2" => 0x3C,
        "F3" => 0x3D,
        "F4" => 0x3E,
        "F5" => 0x3F,
        "F6" => 0x40,
        "F7" => 0x41,
        "F8" => 0x42,
        "F9" => 0x43,
        "F10" => 0x44,
        "NumLock" => 0x45,
        "ScrollLock" => 0x46,
        "Numpad7" => 0x47,
        "Numpad8" => 0x48,
        "Numpad9" => 0x49,
        "NumpadSubtract" => 0x4A,
        "Numpad4" => 0x4B,
        "Numpad5" => 0x4C,
        "Numpad6" => 0x4D,
        "NumpadAdd" => 0x4E,
        "Numpad1" => 0x4F,
        "Numpad2" => 0x50,
        "Numpad3" => 0x51,
        "Numpad0" => 0x52,
        "NumpadDecimal" => 0x53,
        "F11" => 0x57,
        "F12" => 0x58,
        // Extended keys (0xE0xx)
        "NumpadEnter" => 0xE01C,
        "ControlRight" => 0xE01D,
        "NumpadDivide" => 0xE035,
        "PrintScreen" => 0xE037,
        "AltRight" => 0xE038,
        "Home" => 0xE047,
        "ArrowUp" => 0xE048,
        "PageUp" => 0xE049,
        "ArrowLeft" => 0xE04B,
        "ArrowRight" => 0xE04D,
        "End" => 0xE04F,
        "ArrowDown" => 0xE050,
        "PageDown" => 0xE051,
        "Insert" => 0xE052,
        "Delete" => 0xE053,
        "MetaLeft" | "OSLeft" => 0xE05B,
        "MetaRight" | "OSRight" => 0xE05C,
        "ContextMenu" => 0xE05D,
        _ => 0,
    }
}

fn encode_region_as_png(
    image: &DecodedImage,
    x: u16,
    y: u16,
    width: u16,
    height: u16,
) -> SessionResult<Vec<u8>> {
    let fb = image.data();
    let fb_width = image.width() as usize;
    let x = x as usize;
    let y = y as usize;
    let w = width as usize;
    let h = height as usize;

    // RDP framebuffer is RGBx32: the alpha channel is undefined (typically 0)
    // because ALLOW_SKIP_ALPHA is set. Extract only R, G, B channels to avoid
    // transparent pixels when rendered on an HTML canvas.
    let mut region_buf = Vec::with_capacity(w * h * 3);
    for row in y..y + h {
        let row_start = (row * fb_width + x) * 4;
        let row_end = row_start + w * 4;
        if row_end <= fb.len() {
            for pixel in fb[row_start..row_end].chunks_exact(4) {
                region_buf.push(pixel[0]); // R
                region_buf.push(pixel[1]); // G
                region_buf.push(pixel[2]); // B
            }
        }
    }

    let mut png_data = Vec::new();
    let encoder = PngEncoder::new(&mut png_data);
    #[allow(clippy::cast_possible_truncation)]
    encoder
        .write_image(&region_buf, w as u32, h as u32, ExtendedColorType::Rgb8)
        .map_err(|e| SessionError::PngEncodingFailed(e.to_string()))?;

    Ok(png_data)
}

/// VAU-001: build the TLS client config used by the **session** path.
///
/// Unlike the pre-fix `NoCertificateVerification` (which accepted every
/// certificate and exposed each RDP session to a trivial MITM), this
/// config installs a [`PinningServerCertVerifier`] that:
///
/// 1. refuses the handshake unless the live server's SPKI SHA-256
///    fingerprint matches `expected_fingerprint` (the value pinned by an
///    admin via the TOFU fetch workflow), and
/// 2. still cryptographically verifies the handshake signature (delegated
///    to the aws-lc-rs `CryptoProvider`), so a MITM that merely replays the
///    pinned certificate without holding the private key is rejected.
///
/// RDP targets are typically self-signed and addressed by IP, so classic
/// WebPKI chain / hostname validation is inapplicable; SPKI pinning is the
/// SSH-host-key-equivalent trust anchor.
fn build_tls_config(expected_fingerprint: &str) -> SessionResult<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinningServerCertVerifier {
        expected_fingerprint: expected_fingerprint.to_string(),
        provider: Arc::clone(&provider),
    });

    let mut config = rustls::client::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SessionError::TlsUpgradeFailed(format!("TLS provider init failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    // CredSSP does not support TLS session resumption
    config.resumption = rustls::client::Resumption::disabled();

    Ok(Arc::new(config))
}

/// Compute the `SHA256:<base64>` fingerprint of a certificate's full
/// `SubjectPublicKeyInfo` DER (algorithm identifier + public key), NOT just
/// the raw key BIT STRING. Hashing the complete SPKI prevents key/algorithm
/// confusion and matches the value an admin pins via the TOFU fetch flow.
pub(crate) fn spki_sha256_fingerprint(
    cert: &pki_types::CertificateDer<'_>,
) -> Result<String, String> {
    let spki = spki_der(cert)?;
    let digest = Sha256::digest(&spki);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Re-encode a certificate's `SubjectPublicKeyInfo` to DER bytes.
pub(crate) fn spki_der(cert: &pki_types::CertificateDer<'_>) -> Result<Vec<u8>, String> {
    use x509_cert::der::{Decode as _, Encode as _};
    let parsed = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("Failed to re-encode SubjectPublicKeyInfo: {e}"))
}

/// Constant-time byte comparison (avoids leaking the position of the first
/// differing byte of the pinned fingerprint via timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// VAU-001 session-path verifier: pins the server SPKI and verifies the
/// handshake signature against the crypto provider.
#[derive(Debug)]
struct PinningServerCertVerifier {
    /// Expected `SHA256:<base64>` fingerprint of the server SPKI.
    expected_fingerprint: String,
    /// Crypto provider used to verify the TLS handshake signature.
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinningServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let live = spki_sha256_fingerprint(end_entity)
            .map_err(|e| rustls::Error::General(format!("SPKI extraction failed: {e}")))?;

        if constant_time_eq(live.as_bytes(), self.expected_fingerprint.as_bytes()) {
            Ok(ServerCertVerified::assertion())
        } else {
            // The wording carries "certificate mismatch" and "MITM" so the
            // vauban-web connect handler can flip rdp_server_cert_mismatch.
            Err(rustls::Error::General(format!(
                "RDP server certificate mismatch - possible MITM. \
                 Expected pinned SPKI {expected}, server presented {live}. \
                 An admin must re-fetch and pin the new certificate.",
                expected = self.expected_fingerprint,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// VAU-001 TOFU fetch: open a minimal RDP/X.224 + TLS handshake to the
/// target, extract the server's `SubjectPublicKeyInfo`, and return its
/// base64 DER + `SHA256:<base64>` fingerprint WITHOUT performing CredSSP /
/// NLA. Used only by the admin "fetch + pin" workflow; the connection is
/// closed as soon as the certificate is read.
///
/// Trust model: this path uses [`TofuAcceptAnyFetchVerifier`] (accept-any)
/// because nothing is pinned yet -- exactly like SSH `fetch_host_key`
/// accepting the live key on first fetch. Security is provided downstream:
/// the admin reviews the fingerprint before pinning, and the session path
/// ([`build_tls_config`] + [`PinningServerCertVerifier`]) enforces the pin
/// fail-closed.
pub async fn fetch_server_cert(
    host: &str,
    port: u16,
    preconnected_fd: Option<OwnedFd>,
) -> SessionResult<(String, String)> {
    let stream = if let Some(fd) = preconnected_fd {
        // SAFETY: the FD comes from the supervisor via SCM_RIGHTS and is a
        // valid, connected TCP socket.
        let std_stream = unsafe { std::net::TcpStream::from_raw_fd(fd.into_raw_fd()) };
        std_stream.set_nonblocking(true).map_err(|e| {
            SessionError::ConnectionFailed(format!("Failed to set non-blocking: {e}"))
        })?;
        TcpStream::from_std(std_stream).map_err(|e| {
            SessionError::ConnectionFailed(format!("Failed to create tokio stream: {e}"))
        })?
    } else {
        // Non-sandboxed mode (development/macOS): resolve + connect directly.
        let addr_str = format!("{host}:{port}");
        let server_addr = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host(&addr_str),
        )
        .await
        .map_err(|_| SessionError::ConnectionFailed("DNS resolution timed out".to_string()))?
        .map_err(|e| SessionError::ConnectionFailed(format!("DNS resolution failed: {e}")))?
        .next()
        .ok_or_else(|| SessionError::ConnectionFailed("No addresses resolved".to_string()))?;

        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(server_addr),
        )
        .await
        .map_err(|_| {
            SessionError::ConnectionFailed(format!("TCP connect to {host}:{port} timed out"))
        })?
        .map_err(|e| SessionError::ConnectionFailed(format!("TCP connect failed: {e}")))?
    };

    let server_addr = stream
        .peer_addr()
        .map_err(|e| SessionError::ConnectionFailed(format!("peer addr: {e}")))?;
    let client_addr = stream
        .local_addr()
        .map_err(|e| SessionError::ConnectionFailed(format!("local addr: {e}")))?;

    // Dummy credentials: we negotiate up to the TLS upgrade and never run
    // CredSSP, so credentials are never consumed.
    let connector_config = build_connector_config(String::new(), String::new(), None, 1024, 768);
    let mut connector = ClientConnector::new(connector_config, client_addr);
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);

    let _should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| SessionError::ConnectionFailed(format!("RDP handshake begin failed: {e}")))?;

    let server_name: pki_types::ServerName<'static> = host
        .to_string()
        .try_into()
        .unwrap_or_else(|_| pki_types::ServerName::IpAddress(server_addr.ip().into()));

    let tls_config = build_fetch_tls_config()?;
    let tls_connector = tokio_rustls::TlsConnector::from(tls_config);
    let tcp_stream = framed.into_inner_no_leftover();
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls_connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| SessionError::TlsUpgradeFailed("TLS handshake timed out after 10s".to_string()))?
    .map_err(|e| SessionError::TlsUpgradeFailed(e.to_string()))?;

    let (_, client_connection) = tls_stream.get_ref();
    let cert = client_connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or_else(|| {
            SessionError::TlsUpgradeFailed("Server presented no certificate".to_string())
        })?;

    let spki = spki_der(cert).map_err(SessionError::TlsUpgradeFailed)?;
    let fingerprint = spki_sha256_fingerprint(cert).map_err(SessionError::TlsUpgradeFailed)?;
    let spki_b64 = base64::engine::general_purpose::STANDARD.encode(&spki);

    // tls_stream is dropped here -> the connection is closed before CredSSP.
    Ok((spki_b64, fingerprint))
}

/// VAU-001 fetch-only TLS config. Accepts ANY server certificate (TOFU --
/// nothing is pinned yet) but still verifies the handshake signature
/// against the crypto provider. Used EXCLUSIVELY by [`fetch_server_cert`];
/// the session path uses [`build_tls_config`] (pinning). The lint
/// `check_rdp_cert_paths.sh` forbids wiring this verifier into the session
/// path.
fn build_fetch_tls_config() -> SessionResult<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(TofuAcceptAnyFetchVerifier {
        provider: Arc::clone(&provider),
    });

    let mut config = rustls::client::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| SessionError::TlsUpgradeFailed(format!("TLS provider init failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    config.resumption = rustls::client::Resumption::disabled();

    Ok(Arc::new(config))
}

/// TOFU accept-any verifier, confined to the fetch path (see
/// [`build_fetch_tls_config`]).
#[derive(Debug)]
struct TofuAcceptAnyFetchVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for TofuAcceptAnyFetchVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // TOFU: nothing is pinned yet, so accept whatever the server
        // presents so the admin can review and pin its fingerprint. This
        // verifier is NEVER used by the session path.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Minimal NetworkClient for NTLM-only authentication.
/// Kerberos authentication (which requires network access to KDC) is not
/// supported in this initial implementation. For username/password auth
/// with NTLM, the network client is never called.
struct NtlmOnlyNetworkClient;

impl NetworkClient for NtlmOnlyNetworkClient {
    async fn send(
        &mut self,
        _request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> ironrdp::connector::ConnectorResult<Vec<u8>> {
        Err(ironrdp::connector::general_err!(
            "Kerberos not supported: only NTLM authentication is available"
        ))
    }
}

/// Per-exchange budget for a KDC FD lease + local framed I/O. Slightly
/// above the supervisor's `[auth.kerberos].timeout_secs` default (5 s for
/// connect) so the supervisor's error message wins over a bare local timeout.
const KDC_LEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Bound on a KDC TCP reply body (excludes the 4-byte length prefix).
/// Fences a hostile/spoofed KDC from forcing a huge allocation in the proxy.
pub const MAX_KDC_REPLY: usize = 256 * 1024;

/// Build a Kerberos TCP frame: 4-byte big-endian length + body.
///
/// Pure helper (dual of [`decode_kdc_reply_len`]). Production I/O writes
/// frames already assembled by sspi; unit / property tests build frames
/// through this helper so encode/decode stay in lock-step.
#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub fn encode_kdc_request_frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Decode a Kerberos TCP reply length prefix, fencing [`MAX_KDC_REPLY`].
pub fn decode_kdc_reply_len(be: [u8; 4]) -> Result<usize, String> {
    let reply_len = u32::from_be_bytes(be) as usize;
    if reply_len > MAX_KDC_REPLY {
        return Err(format!("KDC reply too large: {reply_len} bytes"));
    }
    Ok(reply_len)
}

/// Handle for leasing Kerberos KDC sockets from the supervisor (SCM_RIGHTS)
/// then performing framed TCP I/O locally. The sealed proxy never
/// `connect()`s; the root TCB never sees Kerberos payload bytes.
///
/// Correlation uses `request_id` (distinct from asset `pending_connections`
/// keyed by `session_id` and from recording leases). `kdc_round_trip`
/// parks a oneshot, sends [`Message::KerberosKdcRequest`] (empty `data`),
/// and `main_loop` completes with the leased [`OwnedFd`] after
/// `recv_fd_timed`.
type KdcLeaseResult = Result<OwnedFd, String>;

pub struct SupervisorRelay {
    tx: mpsc::UnboundedSender<Message>,
    pending: tokio::sync::Mutex<
        std::collections::HashMap<u64, tokio::sync::oneshot::Sender<KdcLeaseResult>>,
    >,
    next_request_id: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for SupervisorRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SupervisorRelay").finish_non_exhaustive()
    }
}

impl SupervisorRelay {
    pub fn new(tx: mpsc::UnboundedSender<Message>) -> Self {
        Self {
            tx,
            pending: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            next_request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Lease a connected KDC FD, write one framed Kerberos TCP message
    /// (AS-REQ / TGS-REQ, 4-byte length prefix included), read the framed
    /// reply, and return it to sspi. Fail-closed on lease / I/O / timeout.
    pub async fn kdc_round_trip(&self, session_id: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(request_id, resp_tx);

        let request = Message::KerberosKdcRequest {
            request_id,
            session_id: session_id.to_string(),
            // Wire field retained for bincode; supervisor ignores payload.
            data: shared::messages::SensitiveBytes::default(),
        };
        if self.tx.send(request).is_err() {
            self.pending.lock().await.remove(&request_id);
            return Err("supervisor KDC lease channel closed".to_string());
        }

        let owned_fd = match tokio::time::timeout(KDC_LEASE_TIMEOUT, resp_rx).await {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => {
                return Err("KDC FD lease response channel dropped".to_string());
            }
            Err(_) => {
                self.pending.lock().await.remove(&request_id);
                return Err(format!(
                    "KDC FD lease timed out after {}s",
                    KDC_LEASE_TIMEOUT.as_secs()
                ));
            }
        };

        // Blocking framed I/O off the tokio worker (same posture as
        // recording FD lease helpers).
        let io_data = data;
        tokio::task::spawn_blocking(move || kdc_framed_round_trip(owned_fd, &io_data))
            .await
            .map_err(|e| format!("KDC I/O task join failed: {e}"))?
    }

    /// Route a leased KDC FD (or lease error) to the parked requester.
    /// Unknown `request_id`s (late replies after a timeout) are dropped.
    pub async fn complete(&self, request_id: u64, result: KdcLeaseResult) {
        if let Some(tx) = self.pending.lock().await.remove(&request_id) {
            let _ = tx.send(result);
        } else {
            debug!(
                request_id,
                "Dropping KDC FD lease with no pending requester"
            );
        }
    }
}

/// Write a framed Kerberos request and read a framed reply on a leased FD.
///
/// Input/`out` include the 4-byte big-endian length prefix (sspi `send_tcp`).
pub fn kdc_framed_round_trip(owned_fd: OwnedFd, request: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};

    // SAFETY: OwnedFd is exclusively ours; convert to TcpStream for I/O.
    let mut stream = unsafe { std::net::TcpStream::from_raw_fd(owned_fd.into_raw_fd()) };
    let timeout = std::time::Duration::from_secs(10);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream
        .write_all(request)
        .map_err(|e| format!("KDC write failed: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("KDC reply length read failed: {e}"))?;
    let reply_len = decode_kdc_reply_len(len_buf)?;

    let mut reply = vec![0u8; reply_len + 4];
    reply[0..4].copy_from_slice(&len_buf);
    stream
        .read_exact(&mut reply[4..])
        .map_err(|e| format!("KDC reply body read failed: {e}"))?;
    Ok(reply)
}

/// NetworkClient for the Kerberos / Restricted Admin mode: every sspi
/// `NetworkRequest` leases a KDC FD from the supervisor
/// ([`Message::KerberosKdcRequest`]) and performs framed TCP I/O locally.
///
/// Posture:
/// - Only `NetworkProtocol::Tcp` is accepted. `Udp` / `Http` / `Https`
///   are refused fail-closed.
/// - The request URL host ([`KERBEROS_KDC_SENTINEL_URL`]) is NOT forwarded:
///   the supervisor always connects to its own configured KDC.
struct KerberosRelayNetworkClient {
    relay: Arc<SupervisorRelay>,
    session_id: String,
}

impl NetworkClient for KerberosRelayNetworkClient {
    async fn send(
        &mut self,
        request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> ironrdp::connector::ConnectorResult<Vec<u8>> {
        use ironrdp::connector::sspi::network_client::NetworkProtocol;

        match request.protocol {
            NetworkProtocol::Tcp => self
                .relay
                .kdc_round_trip(&self.session_id, request.data.clone())
                .await
                .map_err(|e| {
                    warn!(session_id = %self.session_id, error = %e, "KDC FD round-trip failed");
                    ironrdp::connector::custom_err!("KDC FD", std::io::Error::other(e))
                }),
            NetworkProtocol::Udp | NetworkProtocol::Http | NetworkProtocol::Https => {
                Err(ironrdp::connector::general_err!(
                    "KDC path refuses non-TCP transports (fail-closed)"
                ))
            }
        }
    }
}

/// NetworkClient actually plugged into the CredSSP sequence, selected from
/// the session's [`RdpAuthMode`]. An enum (rather than a trait object)
/// because `ironrdp_tokio::NetworkClient::send` is an RPITIT and is not
/// dyn-compatible.
enum SessionNetworkClient {
    NtlmOnly(NtlmOnlyNetworkClient),
    KerberosRelay(KerberosRelayNetworkClient),
}

impl SessionNetworkClient {
    /// Fail-closed selection: Kerberos mode WITHOUT a supervisor relay
    /// (e.g. non-sandboxed dev mode where no FD-passing state exists) is
    /// refused instead of silently downgrading to NTLM.
    fn for_auth_mode(
        auth_mode: RdpAuthMode,
        relay: Option<Arc<SupervisorRelay>>,
        session_id: &str,
    ) -> SessionResult<Self> {
        match auth_mode {
            RdpAuthMode::Ntlm => Ok(Self::NtlmOnly(NtlmOnlyNetworkClient)),
            RdpAuthMode::KerberosRestrictedAdmin => match relay {
                Some(relay) => Ok(Self::KerberosRelay(KerberosRelayNetworkClient {
                    relay,
                    session_id: session_id.to_string(),
                })),
                None => Err(SessionError::AuthenticationFailed(
                    "Kerberos mode requires the supervisor KDC FD broker (no NTLM fallback)"
                        .to_string(),
                )),
            },
        }
    }
}

impl NetworkClient for SessionNetworkClient {
    async fn send(
        &mut self,
        request: &ironrdp::connector::sspi::generator::NetworkRequest,
    ) -> ironrdp::connector::ConnectorResult<Vec<u8>> {
        match self {
            Self::NtlmOnly(client) => client.send(request).await,
            Self::KerberosRelay(client) => client.send(request).await,
        }
    }
}

/// Classification of an inbound PDU against the MCS message channel during
/// the connection finalize sequence.
#[derive(Debug, PartialEq, Eq)]
enum MessageChannelPdu {
    /// RTT Measure Request ([MS-RDPBCGR] 2.2.14.1.1): must be answered with
    /// an RTT Measure Response so the server can compute the round-trip time.
    RttRequest { sequence_number: u16 },
    /// Any other message-channel PDU (bandwidth measure, network
    /// characteristics result, ...). Informational during the connection
    /// sequence: swallowed without a reply, mirroring the upstream
    /// `ConnectTimeAutoDetection` handling.
    Other,
}

/// Demultiplex one inbound PDU by MCS channel during connection finalize.
///
/// IronRDP >= 0.17 unconditionally requests the MCS message channel and
/// advertises `SUPPORT_NET_CHAR_AUTODETECT` in the client GCC blocks, so the
/// server may interleave connect-time auto-detect PDUs (carried on the
/// message channel) with the licensing exchange ([MS-RDPBCGR] 1.3.8). The
/// upstream connector only demuxes those in its pre-licensing
/// `ConnectTimeAutoDetection` state: a message-channel PDU arriving
/// mid-licensing is handed to the license decoder and aborts the connection
/// with `decode during SERVER_NEW_LICENSE/... decode error` (its security
/// header carries `SEC_AUTODETECT_REQ`, not `LICENSE_PKT`).
///
/// Returns `None` when the PDU is NOT on the message channel (it must then
/// be fed to the connector state machine as usual), and
/// `Some(MessageChannelPdu)` when it is (it must NEVER reach the connector).
fn classify_message_channel_pdu(
    pdu: &[u8],
    message_channel_id: Option<u16>,
) -> Option<MessageChannelPdu> {
    use ironrdp::pdu::mcs::McsMessage;
    use ironrdp::pdu::rdp::autodetect::{AutoDetectReqPdu, AutoDetectRequest};
    use ironrdp::pdu::x224::X224;

    let message_channel_id = message_channel_id?;
    let mcs = ironrdp::core::decode::<X224<McsMessage<'_>>>(pdu).ok()?;
    let McsMessage::SendDataIndication(data) = mcs.0 else {
        return None;
    };
    if data.channel_id != message_channel_id {
        return None;
    }

    match ironrdp::core::decode::<AutoDetectReqPdu>(&data.user_data) {
        Ok(AutoDetectReqPdu {
            request:
                AutoDetectRequest::RttRequest {
                    sequence_number, ..
                },
            ..
        }) => Some(MessageChannelPdu::RttRequest { sequence_number }),
        _ => Some(MessageChannelPdu::Other),
    }
}

/// Encode the answer to a connect-time RTT Measure Request into `buf`.
///
/// Mirrors the upstream `respond_to_connect_time_autodetect` (private in
/// ironrdp-connector): only RTT is answered, the response goes out as an
/// MCS Send Data Request on the message channel. Returns the number of
/// bytes written into `buf` (`None` when no response is warranted).
/// Synchronous on purpose: `&ClientConnector` is not `Sync`, so it must not
/// be held across an await point in a spawned task.
fn encode_rtt_response(
    connector: &ClientConnector,
    buf: &mut WriteBuf,
    sequence_number: u16,
) -> ConnectorResult<Option<usize>> {
    use ironrdp::pdu::rdp::autodetect::{AutoDetectResponse, AutoDetectRspPdu};

    let Some(message_channel_id) = connector.message_channel_id else {
        return Ok(None);
    };
    let user_channel_id = match &connector.state {
        ClientConnectorState::ConnectTimeAutoDetection {
            user_channel_id, ..
        }
        | ClientConnectorState::LicensingExchange {
            user_channel_id, ..
        }
        | ClientConnectorState::MultitransportBootstrapping {
            user_channel_id, ..
        } => *user_channel_id,
        _ => {
            debug!("RTT request received in a phase without a known user channel; ignored");
            return Ok(None);
        }
    };

    buf.clear();
    let response = AutoDetectRspPdu::new(AutoDetectResponse::RttResponse { sequence_number });
    let len =
        connector::encode_send_data_request(user_channel_id, message_channel_id, &response, buf)?;

    Ok(Some(len))
}

/// Outcome of one iteration of the demuxed finalize loop
/// ([`finalize_step`]). Exposed as a value so tests can drive the loop one
/// PDU at a time against a scripted transport.
#[derive(Debug, PartialEq, Eq)]
enum FinalizeStepOutcome {
    /// The PDU (or a no-input step) was fed to the connector state machine.
    SteppedConnector,
    /// An RTT Measure Request on the message channel was answered (or
    /// dropped when no channel was usable); the connector was NOT stepped.
    AnsweredRtt,
    /// A non-RTT message-channel PDU was swallowed; the connector was NOT
    /// stepped.
    IgnoredMessageChannelPdu,
}

/// One iteration of the demuxed finalize loop: read the next PDU, demux it
/// by MCS channel, and either handle it locally (message channel) or feed it
/// to the connector (everything else), flushing any connector response.
async fn finalize_step<S>(
    connector: &mut ClientConnector,
    framed: &mut Framed<S>,
    buf: &mut WriteBuf,
) -> ConnectorResult<FinalizeStepOutcome>
where
    S: FramedRead + FramedWrite,
{
    buf.clear();

    let written = if let Some(next_pdu_hint) = connector.next_pdu_hint() {
        let pdu = framed
            .read_by_hint(next_pdu_hint)
            .await
            .map_err(|e| ironrdp::connector::custom_err!("read frame by hint", e))?;

        match classify_message_channel_pdu(&pdu, connector.message_channel_id) {
            Some(MessageChannelPdu::RttRequest { sequence_number }) => {
                debug!(
                    sequence_number,
                    "Answering RTT measure request received during connection finalize"
                );
                if let Some(len) = encode_rtt_response(connector, buf, sequence_number)? {
                    framed
                        .write_all(&buf[..len])
                        .await
                        .map_err(|e| ironrdp::connector::custom_err!("write all", e))?;
                }
                return Ok(FinalizeStepOutcome::AnsweredRtt);
            }
            Some(MessageChannelPdu::Other) => {
                debug!("Ignoring non-licensing message-channel PDU during connection finalize");
                return Ok(FinalizeStepOutcome::IgnoredMessageChannelPdu);
            }
            None => connector.step(&pdu, buf)?,
        }
    } else {
        connector.step_no_input(buf)?
    };

    if let Some(response_len) = written.size() {
        framed
            .write_all(&buf[..response_len])
            .await
            .map_err(|e| ironrdp::connector::custom_err!("write all", e))?;
    }

    Ok(FinalizeStepOutcome::SteppedConnector)
}

/// Local mirror of `ironrdp_tokio::connect_begin` (Kerberos phase A,
/// audit §7 / "point 7"): behaviorally identical to the upstream loop, with
/// ONE addition -- the first outbound PDU (always the X.224 Connection
/// Request, [MS-RDPBCGR] 2.2.1.1) is decoded, `extra_flags` are OR-ed into
/// its RDP_NEG_REQ flags, and the PDU is re-encoded before hitting the
/// wire. `ironrdp-connector 0.10` hardcodes `RequestFlags::empty()` in
/// `connection.rs` and exposes no hook, so Restricted Admin mode
/// (`RESTRICTED_ADMIN_MODE_REQUIRED`) is impossible without this mirror
/// (implemented locally: neither fork nor upstream patch, per the phase-A
/// scoping decision).
///
/// The `ShouldUpgrade` token is obtained through the public
/// `ironrdp_tokio::skip_connect_begin` (the type is `#[non_exhaustive]`
/// and cannot be constructed here).
async fn connect_begin_with_nego_flags<S>(
    framed: &mut Framed<S>,
    connector: &mut ClientConnector,
    extra_flags: nego::RequestFlags,
) -> ConnectorResult<ironrdp_tokio::ShouldUpgrade>
where
    S: Sync + FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();
    // Nothing to patch when no extra flag is requested (NTLM mode): the
    // first PDU is then written verbatim, byte-identical to upstream.
    let mut connection_request_patched = extra_flags.is_empty();

    while !connector.should_perform_security_upgrade() {
        buf.clear();
        let written = if let Some(next_pdu_hint) = connector.next_pdu_hint() {
            let pdu = framed
                .read_by_hint(next_pdu_hint)
                .await
                .map_err(|e| ironrdp::connector::custom_err!("read frame by hint", e))?;
            connector.step(&pdu, &mut buf)?
        } else {
            connector.step_no_input(&mut buf)?
        };

        if let Some(response_len) = written.size() {
            if connection_request_patched {
                framed
                    .write_all(&buf[..response_len])
                    .await
                    .map_err(|e| ironrdp::connector::custom_err!("write all", e))?;
            } else {
                connection_request_patched = true;
                let patched = patch_connection_request_flags(&buf[..response_len], extra_flags)?;
                framed
                    .write_all(&patched)
                    .await
                    .map_err(|e| ironrdp::connector::custom_err!("write all", e))?;
            }
        }
    }

    Ok(ironrdp_tokio::skip_connect_begin(connector))
}

/// Decode an X.224 Connection Request PDU, OR `extra_flags` into its
/// RDP_NEG_REQ flags, and re-encode it. Errors are fail-closed: a PDU that
/// does not decode as a Connection Request aborts the handshake rather than
/// being silently written unpatched (the flag is a security property in
/// Restricted Admin mode).
fn patch_connection_request_flags(
    pdu: &[u8],
    extra_flags: nego::RequestFlags,
) -> ConnectorResult<Vec<u8>> {
    let X224(mut request): X224<nego::ConnectionRequest> = ironrdp::core::decode(pdu)
        .map_err(|e| ironrdp::connector::custom_err!("decode X224 ConnectionRequest", e))?;
    request.flags |= extra_flags;
    ironrdp::core::encode_vec(&X224(request))
        .map_err(|e| ironrdp::connector::custom_err!("encode X224 ConnectionRequest", e))
}

/// Local replacement for `ironrdp_tokio::connect_finalize` that shields the
/// connector state machine from message-channel PDUs.
///
/// Identical to the upstream loop (CredSSP, then step the connector until
/// `Connected`), with ONE addition: every inbound PDU is first passed through
/// [`classify_message_channel_pdu`]; message-channel PDUs are answered
/// (RTT) or swallowed instead of being fed to the connector. This closes the
/// upstream gap where an auto-detect PDU interleaved with the licensing
/// exchange kills the connection with a license decode error.
async fn connect_finalize_with_message_channel_demux<S, N>(
    _upgraded: Upgraded,
    mut connector: ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    server_name: connector::ServerName,
    server_public_key: Vec<u8>,
    auth_mode: RdpAuthMode,
) -> ConnectorResult<ConnectionResult>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    let mut buf = WriteBuf::new();

    if connector.should_perform_credssp() {
        perform_credssp_step(
            &mut connector,
            framed,
            network_client,
            &mut buf,
            server_name,
            server_public_key,
            auth_mode,
        )
        .await?;
    }

    let result = loop {
        finalize_step(&mut connector, framed, &mut buf).await?;

        if let ClientConnectorState::Connected { result } = connector.state {
            break result;
        }
    };

    Ok(result)
}

/// CredSSP/NLA sequence, mirrored from `ironrdp_async::connect_finalize`
/// (the upstream helper is private). In NTLM mode the historical posture is
/// preserved bit-for-bit ([`NtlmOnlyNetworkClient`] refuses any network
/// request). In Kerberos / Restricted Admin mode the sequence runs
/// credential-less and the network client relays KDC exchanges to the
/// supervisor.
async fn perform_credssp_step<S, N>(
    connector: &mut ClientConnector,
    framed: &mut Framed<S>,
    network_client: &mut N,
    buf: &mut WriteBuf,
    server_name: connector::ServerName,
    server_public_key: Vec<u8>,
    auth_mode: RdpAuthMode,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    let selected_protocol = match connector.state {
        ClientConnectorState::Credssp {
            selected_protocol, ..
        } => selected_protocol,
        _ => {
            return Err(ironrdp::connector::general_err!(
                "invalid connector state for CredSSP sequence"
            ));
        }
    };

    let (mut sequence, mut ts_request) = LocalCredsspSequence::init(
        &connector.config.credentials,
        connector.config.domain.as_deref(),
        selected_protocol,
        server_name,
        server_public_key,
        auth_mode,
    )?;

    loop {
        let client_state = {
            let mut generator = sequence.process_ts_request(ts_request);
            let mut state = generator.start();
            loop {
                match state {
                    GeneratorState::Suspended(request) => {
                        let response = network_client.send(&request).await?;
                        state = generator.resume(Ok(response));
                    }
                    GeneratorState::Completed(client_state) => {
                        break client_state.map_err(|e| {
                            ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e))
                        });
                    }
                }
            }?
        };

        buf.clear();
        let written = sequence.handle_process_result(client_state, buf)?;

        if let Some(response_len) = written.size() {
            framed
                .write_all(&buf[..response_len])
                .await
                .map_err(|e| ironrdp::connector::custom_err!("write all", e))?;
        }

        let Some(next_pdu_hint) = sequence.next_pdu_hint() else {
            break;
        };

        let pdu = framed
            .read_by_hint(next_pdu_hint)
            .await
            .map_err(|e| ironrdp::connector::custom_err!("read frame by hint", e))?;

        if let Some(next_request) = sequence.decode_server_message(&pdu)? {
            ts_request = next_request;
        } else {
            break;
        }
    }

    connector.mark_credssp_as_done();

    Ok(())
}

/// Sentinel KDC URL handed to sspi in Kerberos mode.
///
/// sspi 0.21.2 resolves the KDC as follows when `KerberosConfig.kdc_url` is
/// `None`: `SSPI_KDC_URL*` env vars, then `/etc/krb5.conf`, then DNS SRV --
/// all unavailable inside the sealed sandbox. Providing a `tcp://` URL
/// short-circuits that detection (`Kerberos::get_kdc` uses the pinned URL
/// verbatim) and forces every KDC exchange through a
/// `NetworkRequest { protocol: Tcp, .. }`. The HOST part is meaningless by
/// design: the supervisor relay ignores it and always connects to its own
/// `[auth.kerberos]` configured KDC (SSRF-safe by construction).
const KERBEROS_KDC_SENTINEL_URL: &str = "tcp://kdc-via-supervisor:88";

/// PDU hint for a CredSSP TsRequest frame (local mirror of the private
/// upstream `CredsspTsRequestHint`).
#[derive(Clone, Copy, Debug)]
struct CredsspTsRequestHint;

const CREDSSP_TS_REQUEST_HINT: CredsspTsRequestHint = CredsspTsRequestHint;

impl PduHint for CredsspTsRequestHint {
    fn find_size(&self, bytes: &[u8]) -> ironrdp::core::DecodeResult<Option<(bool, usize)>> {
        match sspi_credssp::TsRequest::read_length(bytes) {
            Ok(length) => Ok(Some((true, length))),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(ironrdp::core::other_err_with_source(
                "CredsspTsRequestHint",
                "invalid TsRequest length",
                e,
            )),
        }
    }
}

/// PDU hint for an Early User Authorization Result frame (local mirror of
/// the private upstream `CredsspEarlyUserAuthResultHint`).
#[derive(Clone, Copy, Debug)]
struct CredsspEarlyUserAuthResultHint;

const CREDSSP_EARLY_USER_AUTH_RESULT_HINT: CredsspEarlyUserAuthResultHint =
    CredsspEarlyUserAuthResultHint;

impl PduHint for CredsspEarlyUserAuthResultHint {
    fn find_size(&self, _: &[u8]) -> ironrdp::core::DecodeResult<Option<(bool, usize)>> {
        Ok(Some((true, sspi_credssp::EARLY_USER_AUTH_RESULT_PDU_SIZE)))
    }
}

#[derive(Debug, PartialEq)]
enum LocalCredsspState {
    Ongoing,
    EarlyUserAuthResult,
    Finished,
}

/// Local mirror of `ironrdp-connector 0.10`'s `CredsspSequence` (Kerberos
/// phase A, audit §7 / "point 7").
///
/// Upstream hardcodes `CredSspMode::WithCredentials` (`credssp.rs` L161) and
/// derives the sspi `ClientMode` solely from an optional KDC-proxy config,
/// so neither Restricted Admin (credential-less TSCredentials) nor a
/// fail-closed Kerberos-only package list is reachable through its API. This
/// mirror keeps the exact upstream state machine (Ongoing ->
/// EarlyUserAuthResult -> Finished, same PduHints, same TsRequest wire
/// handling -- everything it touches is public in `sspi 0.21`) and
/// parameterizes the posture by [`RdpAuthMode`]:
///
/// - `Ntlm`: `ClientMode::Ntlm` + `WithCredentials`, byte-identical to the
///   historical behavior.
/// - `KerberosRestrictedAdmin`: `ClientMode::Negotiate` restricted to the
///   `kerberos` package (an NTLM downgrade attempt by the server FAILS the
///   sequence instead of silently delegating the password) +
///   `CredentialLess` (the TSCredentials sent after `pubKeyAuth` carry an
///   EMPTY identity; the password only feeds the in-memory AS-REQ
///   pre-authentication).
#[derive(Debug)]
struct LocalCredsspSequence {
    client: CredSspClient,
    state: LocalCredsspState,
    selected_protocol: nego::SecurityProtocol,
}

impl LocalCredsspSequence {
    /// `server_name` must be the actual target server hostname; it seeds
    /// both the `TERMSRV/<host>` SPN and the sspi client computer name
    /// (mirroring upstream).
    fn init(
        credentials: &Credentials,
        domain: Option<&str>,
        protocol: nego::SecurityProtocol,
        server_name: connector::ServerName,
        server_public_key: Vec<u8>,
        auth_mode: RdpAuthMode,
    ) -> ConnectorResult<(Self, sspi_credssp::TsRequest)> {
        let sspi_credentials: sspi::Credentials = match credentials {
            Credentials::UsernamePassword { username, password } => {
                let username = sspi::Username::new(username, domain)
                    .map_err(|e| ironrdp::connector::custom_err!("invalid username", e))?;
                sspi::AuthIdentity {
                    username,
                    password: password.to_owned().into(),
                }
                .into()
            }
            _ => {
                return Err(ironrdp::connector::general_err!(
                    "only username/password credentials are supported"
                ));
            }
        };

        let server_name = server_name.into_inner();
        let service_principal_name = format!("TERMSRV/{server_name}");

        let (credssp_mode, client_mode) = match auth_mode {
            RdpAuthMode::Ntlm => (
                CredSspMode::WithCredentials,
                sspi_credssp::ClientMode::Ntlm(sspi::ntlm::NtlmConfig::default()),
            ),
            RdpAuthMode::KerberosRestrictedAdmin => {
                let kdc_url = sspi::kerberos::config::parse_kdc_url(KERBEROS_KDC_SENTINEL_URL);
                let kerberos_config = sspi::KerberosConfig {
                    kdc_url,
                    client_computer_name: server_name.clone(),
                };
                (
                    CredSspMode::CredentialLess,
                    sspi_credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
                        protocol_config: Box::new(kerberos_config),
                        // Fail-closed: only the Kerberos package is
                        // permitted; a server-driven NTLM downgrade aborts
                        // the sequence.
                        package_list: Some("kerberos".to_owned()),
                        client_computer_name: server_name,
                    }),
                )
            }
        };

        let client = CredSspClient::new(
            server_public_key,
            sspi_credentials,
            credssp_mode,
            client_mode,
            service_principal_name,
        )
        .map_err(|e| ConnectorError::new("CredSSP", ConnectorErrorKind::Credssp(e)))?;

        let sequence = Self {
            client,
            state: LocalCredsspState::Ongoing,
            selected_protocol: protocol,
        };

        let initial_request = sspi_credssp::TsRequest::default();

        Ok((sequence, initial_request))
    }

    fn next_pdu_hint(&self) -> Option<&dyn PduHint> {
        match self.state {
            LocalCredsspState::Ongoing => Some(&CREDSSP_TS_REQUEST_HINT),
            LocalCredsspState::EarlyUserAuthResult => Some(&CREDSSP_EARLY_USER_AUTH_RESULT_HINT),
            LocalCredsspState::Finished => None,
        }
    }

    /// Returns `Some(ts_request)` when a TS request is received from the
    /// server, and `None` when an early user auth result PDU is received
    /// instead.
    fn decode_server_message(
        &mut self,
        input: &[u8],
    ) -> ConnectorResult<Option<sspi_credssp::TsRequest>> {
        match self.state {
            LocalCredsspState::Ongoing => {
                let message = sspi_credssp::TsRequest::from_buffer(input)
                    .map_err(|e| ironrdp::connector::custom_err!("TsRequest", e))?;
                Ok(Some(message))
            }
            LocalCredsspState::EarlyUserAuthResult => {
                let early_user_auth_result = sspi_credssp::EarlyUserAuthResult::from_buffer(input)
                    .map_err(|e| ironrdp::connector::custom_err!("EarlyUserAuthResult", e))?;

                match early_user_auth_result {
                    sspi_credssp::EarlyUserAuthResult::Success => {
                        self.state = LocalCredsspState::Finished;
                        Ok(None)
                    }
                    sspi_credssp::EarlyUserAuthResult::AccessDenied => Err(ConnectorError::new(
                        "CredSSP",
                        ConnectorErrorKind::AccessDenied,
                    )),
                }
            }
            LocalCredsspState::Finished => Err(ironrdp::connector::general_err!(
                "attempted to feed server request to CredSSP sequence in an unexpected state"
            )),
        }
    }

    fn process_ts_request(
        &mut self,
        request: sspi_credssp::TsRequest,
    ) -> sspi::generator::Generator<
        '_,
        sspi::generator::NetworkRequest,
        sspi::Result<Vec<u8>>,
        sspi::Result<ClientState>,
    > {
        self.client.process(request)
    }

    fn handle_process_result(
        &mut self,
        result: ClientState,
        output: &mut WriteBuf,
    ) -> ConnectorResult<Written> {
        let (size, next_state) = match self.state {
            LocalCredsspState::Ongoing => {
                let (ts_request_from_client, next_state) = match result {
                    ClientState::ReplyNeeded(ts_request) => {
                        (ts_request, LocalCredsspState::Ongoing)
                    }
                    ClientState::FinalMessage(ts_request) => (
                        ts_request,
                        if self
                            .selected_protocol
                            .contains(nego::SecurityProtocol::HYBRID_EX)
                        {
                            LocalCredsspState::EarlyUserAuthResult
                        } else {
                            LocalCredsspState::Finished
                        },
                    ),
                };

                let written = write_credssp_request(ts_request_from_client, output)?;

                Ok((Written::from_size(written)?, next_state))
            }
            LocalCredsspState::EarlyUserAuthResult => {
                Ok((Written::Nothing, LocalCredsspState::Finished))
            }
            LocalCredsspState::Finished => Err(ironrdp::connector::general_err!(
                "CredSSP sequence is already done"
            )),
        }?;

        self.state = next_state;

        Ok(size)
    }
}

/// Encode a client TsRequest into the output buffer (local mirror of the
/// private upstream `write_credssp_request`).
fn write_credssp_request(
    ts_request: sspi_credssp::TsRequest,
    output: &mut WriteBuf,
) -> ConnectorResult<usize> {
    let length = usize::from(ts_request.buffer_len());

    let unfilled_buffer = output.unfilled_to(length);

    ts_request
        .encode_ts_request(unfilled_buffer)
        .map_err(|e| ironrdp::connector::custom_err!("TsRequest", e))?;

    output.advance(length);

    Ok(length)
}

/// Parameters renegotiated by a completed Deactivation-Reactivation
/// Sequence ([MS-RDPBCGR] 1.3.1.3): the server-negotiated desktop size, the
/// new share id, the pointer settings, and the (invariant) MCS channel ids
/// needed to rebuild the fastpath processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReactivationOutcome {
    desktop_size: DesktopSize,
    share_id: u32,
    enable_server_pointer: bool,
    pointer_software_rendering: bool,
    io_channel_id: u16,
    user_channel_id: u16,
}

/// Drive a full Deactivation-Reactivation Sequence: create a fresh
/// activation sequence from the factory (IronRDP 0.17 pattern for the unit
/// `ActiveStageOutput::DeactivateAll` variant) and step it through the
/// Capabilities Exchange and Connection Finalization phases until it
/// reaches `Finalized`, returning the renegotiated session parameters.
async fn drive_reactivation<S>(
    activation_factory: &ConnectionActivationFactory,
    framed: &mut Framed<S>,
) -> ConnectorResult<ReactivationOutcome>
where
    S: FramedRead + FramedWrite,
{
    let mut connection_activation = activation_factory.create();
    let mut buf = WriteBuf::new();

    loop {
        single_sequence_step(framed, &mut connection_activation, &mut buf).await?;

        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
        } = connection_activation.connection_activation_state()
        {
            return Ok(ReactivationOutcome {
                desktop_size,
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                io_channel_id: connection_activation.io_channel_id(),
                user_channel_id: connection_activation.user_channel_id(),
            });
        }
    }
}

fn extract_tls_server_public_key(cert: &pki_types::CertificateDer<'_>) -> Result<Vec<u8>, String> {
    use x509_cert::der::Decode as _;
    let parsed = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|e| format!("Failed to parse X.509 certificate: {e}"))?;
    parsed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| "Public key BIT STRING is not aligned".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== js_code_to_scancode Tests ====================

    #[test]
    fn test_js_code_to_scancode_letters() {
        assert_eq!(js_code_to_scancode("KeyA"), 0x1E);
        assert_eq!(js_code_to_scancode("KeyZ"), 0x2C);
        assert_eq!(js_code_to_scancode("KeyQ"), 0x10);
        assert_eq!(js_code_to_scancode("KeyM"), 0x32);
    }

    #[test]
    fn test_js_code_to_scancode_digits() {
        assert_eq!(js_code_to_scancode("Digit1"), 0x02);
        assert_eq!(js_code_to_scancode("Digit0"), 0x0B);
        assert_eq!(js_code_to_scancode("Digit5"), 0x06);
    }

    #[test]
    fn test_js_code_to_scancode_special_keys() {
        assert_eq!(js_code_to_scancode("Escape"), 0x01);
        assert_eq!(js_code_to_scancode("Enter"), 0x1C);
        assert_eq!(js_code_to_scancode("Space"), 0x39);
        assert_eq!(js_code_to_scancode("Backspace"), 0x0E);
        assert_eq!(js_code_to_scancode("Tab"), 0x0F);
        assert_eq!(js_code_to_scancode("CapsLock"), 0x3A);
    }

    #[test]
    fn test_js_code_to_scancode_modifiers() {
        assert_eq!(js_code_to_scancode("ShiftLeft"), 0x2A);
        assert_eq!(js_code_to_scancode("ShiftRight"), 0x36);
        assert_eq!(js_code_to_scancode("ControlLeft"), 0x1D);
        assert_eq!(js_code_to_scancode("ControlRight"), 0xE01D);
        assert_eq!(js_code_to_scancode("AltLeft"), 0x38);
        assert_eq!(js_code_to_scancode("AltRight"), 0xE038);
    }

    #[test]
    fn test_js_code_to_scancode_function_keys() {
        assert_eq!(js_code_to_scancode("F1"), 0x3B);
        assert_eq!(js_code_to_scancode("F10"), 0x44);
        assert_eq!(js_code_to_scancode("F11"), 0x57);
        assert_eq!(js_code_to_scancode("F12"), 0x58);
    }

    #[test]
    fn test_js_code_to_scancode_arrow_keys() {
        assert_eq!(js_code_to_scancode("ArrowUp"), 0xE048);
        assert_eq!(js_code_to_scancode("ArrowDown"), 0xE050);
        assert_eq!(js_code_to_scancode("ArrowLeft"), 0xE04B);
        assert_eq!(js_code_to_scancode("ArrowRight"), 0xE04D);
    }

    #[test]
    fn test_js_code_to_scancode_navigation() {
        assert_eq!(js_code_to_scancode("Home"), 0xE047);
        assert_eq!(js_code_to_scancode("End"), 0xE04F);
        assert_eq!(js_code_to_scancode("PageUp"), 0xE049);
        assert_eq!(js_code_to_scancode("PageDown"), 0xE051);
        assert_eq!(js_code_to_scancode("Insert"), 0xE052);
        assert_eq!(js_code_to_scancode("Delete"), 0xE053);
    }

    #[test]
    fn test_js_code_to_scancode_numpad() {
        assert_eq!(js_code_to_scancode("Numpad0"), 0x52);
        assert_eq!(js_code_to_scancode("Numpad9"), 0x49);
        assert_eq!(js_code_to_scancode("NumpadEnter"), 0xE01C);
        assert_eq!(js_code_to_scancode("NumpadAdd"), 0x4E);
        assert_eq!(js_code_to_scancode("NumpadSubtract"), 0x4A);
        assert_eq!(js_code_to_scancode("NumpadMultiply"), 0x37);
        assert_eq!(js_code_to_scancode("NumpadDivide"), 0xE035);
        assert_eq!(js_code_to_scancode("NumpadDecimal"), 0x53);
    }

    #[test]
    fn test_js_code_to_scancode_meta_keys() {
        assert_eq!(js_code_to_scancode("MetaLeft"), 0xE05B);
        assert_eq!(js_code_to_scancode("MetaRight"), 0xE05C);
        assert_eq!(js_code_to_scancode("OSLeft"), 0xE05B);
        assert_eq!(js_code_to_scancode("OSRight"), 0xE05C);
    }

    #[test]
    fn test_js_code_to_scancode_punctuation() {
        assert_eq!(js_code_to_scancode("Comma"), 0x33);
        assert_eq!(js_code_to_scancode("Period"), 0x34);
        assert_eq!(js_code_to_scancode("Slash"), 0x35);
        assert_eq!(js_code_to_scancode("Semicolon"), 0x27);
        assert_eq!(js_code_to_scancode("Quote"), 0x28);
        assert_eq!(js_code_to_scancode("BracketLeft"), 0x1A);
        assert_eq!(js_code_to_scancode("BracketRight"), 0x1B);
        assert_eq!(js_code_to_scancode("Backslash"), 0x2B);
        assert_eq!(js_code_to_scancode("Backquote"), 0x29);
        assert_eq!(js_code_to_scancode("Minus"), 0x0C);
        assert_eq!(js_code_to_scancode("Equal"), 0x0D);
    }

    #[test]
    fn test_js_code_to_scancode_unknown_returns_zero() {
        assert_eq!(js_code_to_scancode("UnknownKey"), 0);
        assert_eq!(js_code_to_scancode(""), 0);
        assert_eq!(js_code_to_scancode("FooBar"), 0);
    }

    // ==================== split_scancode Tests ====================

    #[test]
    fn test_split_scancode_normal_key() {
        let (extended, code) = split_scancode(0x1E);
        assert!(!extended);
        assert_eq!(code, 0x1E);
    }

    #[test]
    fn test_split_scancode_extended_key() {
        let (extended, code) = split_scancode(0xE048);
        assert!(extended);
        assert_eq!(code, 0x48);
    }

    #[test]
    fn test_split_scancode_zero() {
        let (extended, code) = split_scancode(0);
        assert!(!extended);
        assert_eq!(code, 0);
    }

    #[test]
    fn test_split_scancode_boundary() {
        let (extended, code) = split_scancode(0xFF);
        assert!(!extended);
        assert_eq!(code, 0xFF);

        let (extended, code) = split_scancode(0x100);
        assert!(extended);
        assert_eq!(code, 0x00);
    }

    // ==================== map_mouse_button Tests ====================

    #[test]
    fn test_map_mouse_button_left() {
        assert!(map_mouse_button(0).is_some());
    }

    #[test]
    fn test_map_mouse_button_middle() {
        assert!(map_mouse_button(1).is_some());
    }

    #[test]
    fn test_map_mouse_button_right() {
        assert!(map_mouse_button(2).is_some());
    }

    #[test]
    fn test_map_mouse_button_x1_x2() {
        assert!(map_mouse_button(3).is_some());
        assert!(map_mouse_button(4).is_some());
    }

    #[test]
    fn test_map_mouse_button_invalid() {
        assert!(map_mouse_button(5).is_none());
        assert!(map_mouse_button(255).is_none());
    }

    // ==================== translate_input_event Tests ====================

    /// Build a high-level Keyboard event with all modifiers/locks off.
    fn keyboard_event(code: &str, key: &str, pressed: bool) -> RdpInputEvent {
        keyboard_event_with_locks(code, key, pressed, false, false, false)
    }

    /// Build a high-level Keyboard event with explicit lock-key states.
    fn keyboard_event_with_locks(
        code: &str,
        key: &str,
        pressed: bool,
        caps_lock: bool,
        num_lock: bool,
        scroll_lock: bool,
    ) -> RdpInputEvent {
        RdpInputEvent::Keyboard {
            code: code.to_string(),
            key: key.to_string(),
            pressed,
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
            caps_lock,
            num_lock,
            scroll_lock,
        }
    }

    #[test]
    fn test_translate_key_pressed() {
        let ops = translate_input_event(RdpInputEvent::KeyPressed { scancode: 0x1E });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_release_all_yields_no_operations() {
        // ReleaseAll is handled by handle_input_event (InputDatabase method,
        // not an Operation); the translation arm must stay empty.
        let ops = translate_input_event(RdpInputEvent::ReleaseAll);
        assert!(ops.is_empty());
    }

    // ==================== handle_input_event Tests ====================

    /// The exact production bug: Shift held, focus lost (keyup never
    /// delivered), ReleaseAll fired on blur. The server must receive the
    /// Shift RELEASE, and a subsequent KeyA press must arrive unshifted.
    #[test]
    fn test_handle_input_release_all_releases_held_modifier() {
        let mut db = InputDatabase::new();
        let mut locks = LockSyncState::default();

        // Shift pressed (scancode 0x2A), keyup lost.
        let pressed = handle_input_event(
            &mut db,
            &mut locks,
            RdpInputEvent::KeyPressed { scancode: 0x2A },
        );
        assert_eq!(pressed.len(), 1);

        // Blur -> ReleaseAll must emit the pending Shift RELEASE.
        let released = handle_input_event(&mut db, &mut locks, RdpInputEvent::ReleaseAll);
        assert_eq!(released.len(), 1, "one RELEASE for the held Shift");
        match &released[0] {
            FastPathInputEvent::KeyboardEvent(flags, scancode) => {
                assert_eq!(*scancode, 0x2A);
                assert!(
                    flags.contains(ironrdp::pdu::input::fast_path::KeyboardFlags::RELEASE),
                    "must be a RELEASE event"
                );
            }
            other => panic!("expected KeyboardEvent, got {other:?}"),
        }

        // Second ReleaseAll is idempotent: nothing left to release.
        let empty = handle_input_event(&mut db, &mut locks, RdpInputEvent::ReleaseAll);
        assert!(empty.is_empty(), "release_all must be idempotent");
    }

    #[test]
    fn test_handle_input_release_all_releases_mouse_buttons() {
        let mut db = InputDatabase::new();
        let mut locks = LockSyncState::default();

        let _ = handle_input_event(
            &mut db,
            &mut locks,
            RdpInputEvent::MouseButtonPressed { button: 0 },
        );
        let released = handle_input_event(&mut db, &mut locks, RdpInputEvent::ReleaseAll);
        assert_eq!(released.len(), 1, "one release for the held button");
    }

    #[test]
    fn test_handle_input_lock_sync_emitted_once_per_state() {
        let mut db = InputDatabase::new();
        let mut locks = LockSyncState::default();

        let caps_on = keyboard_event_with_locks("KeyA", "a", true, true, false, false);
        // First keydown reporting CapsLock=on: SynchronizeEvent + key press.
        let events = handle_input_event(&mut db, &mut locks, caps_on.clone());
        assert_eq!(events.len(), 2, "synchronize + key press");
        assert!(
            matches!(events[0], FastPathInputEvent::SyncEvent(_)),
            "synchronize must precede the key event"
        );

        // Same lock state again: no further SynchronizeEvent (the key
        // itself may repeat as a release+press pair, which is fine).
        let events = handle_input_event(&mut db, &mut locks, caps_on);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, FastPathInputEvent::SyncEvent(_))),
            "no duplicate synchronize for an unchanged lock state"
        );
    }

    #[test]
    fn test_lock_sync_state_reconcile_fires_on_change_only() {
        let mut locks = LockSyncState::default();
        // First report always fires (unknown server state).
        assert!(locks.reconcile(false, false, false).is_some());
        assert!(locks.reconcile(false, false, false).is_none());
        // Any flag change fires again.
        assert!(locks.reconcile(true, false, false).is_some());
        assert!(locks.reconcile(true, false, false).is_none());
        assert!(locks.reconcile(true, true, false).is_some());
        assert!(locks.reconcile(true, true, true).is_some());
    }

    /// Structural pin: the active session loop must route EVERY web input
    /// through handle_input_event (release_all + lock synchronization),
    /// never through a bare translate + apply that would silently drop
    /// the stuck-modifier fix.
    #[test]
    fn test_active_session_loop_routes_input_through_handle_input_event() {
        let source = include_str!("session.rs");
        assert!(
            source.contains("handle_input_event(&mut input_db, &mut lock_sync, input_event)"),
            "SessionCommand::Input must be processed by handle_input_event"
        );
        let input_arm_idx = source
            .find("Some(SessionCommand::Input(input_event))")
            .expect("the loop must handle SessionCommand::Input");
        let arm_end = source[input_arm_idx..]
            .find("Some(SessionCommand::Resize")
            .map(|i| input_arm_idx + i)
            .expect("Resize arm follows the Input arm");
        assert!(
            !source[input_arm_idx..arm_end].contains("input_db.apply(translate_input_event"),
            "the Input arm must not bypass handle_input_event with a direct \
             translate + apply (it would drop ReleaseAll and lock sync)"
        );
    }

    // ==================== Migration guards (IronRDP 0.17) ====================

    /// Extract the locked version of a crate from the isolated Cargo.lock.
    fn locked_version(name: &str) -> String {
        let lock: &str = include_str!("../Cargo.lock");
        let needle = format!("name = \"{name}\"\n");
        let start = lock
            .find(&needle)
            .unwrap_or_else(|| panic!("crate `{name}` must be in Cargo.lock"));
        let rest = &lock[start + needle.len()..];
        let version_line = rest
            .lines()
            .find(|l| l.starts_with("version = "))
            .unwrap_or_else(|| panic!("crate `{name}` must have a version line"));
        version_line
            .trim_start_matches("version = ")
            .trim_matches('"')
            .to_string()
    }

    /// Anti-drift guard: the IronRDP / sspi stack is pinned to the minors
    /// validated by the 0.17 migration. A future `cargo update` that
    /// silently regresses or skips a version (changing API semantics
    /// without a compile error) fails here with an explicit message
    /// instead of surfacing as a runtime behavior change.
    #[test]
    fn test_locked_ironrdp_stack_versions_are_pinned() {
        let expected: [(&str, &str); 8] = [
            ("ironrdp", "0.17."),
            ("ironrdp-connector", "0.10."),
            ("ironrdp-session", "0.11."),
            ("ironrdp-input", "0.7."),
            ("ironrdp-pdu", "0.9."),
            ("ironrdp-async", "0.10."),
            ("ironrdp-tokio", "0.10."),
            ("sspi", "0.21."),
        ];
        for (name, prefix) in expected {
            let version = locked_version(name);
            assert!(
                version.starts_with(prefix),
                "crate `{name}` locked at {version}, expected minor {prefix}x \
                 (validated by the IronRDP 0.17 migration); re-validate the \
                 migration guards before accepting a different minor"
            );
        }
    }

    /// Security posture: the CredSSP network client must refuse EVERY
    /// out-of-band network request (Kerberos KDC lookups over tcp/udp/
    /// http/https). Vauban only supports NTLM inside CredSSP, where the
    /// network client is never called; any call means the target tried
    /// to force a Kerberos exchange and must fail closed.
    #[tokio::test]
    async fn test_ntlm_only_network_client_refuses_all_requests() {
        use ironrdp::connector::sspi::generator::NetworkRequest;
        use ironrdp::connector::sspi::network_client::NetworkProtocol;

        let urls = [
            (NetworkProtocol::Tcp, "tcp://kdc.example.com:88"),
            (NetworkProtocol::Udp, "udp://kdc.example.com:88"),
            (NetworkProtocol::Http, "http://kdc.example.com/KdcProxy"),
            (NetworkProtocol::Https, "https://kdc.example.com/KdcProxy"),
        ];
        for (protocol, url) in urls {
            let request = NetworkRequest {
                protocol,
                url: url::Url::parse(url).expect("static test URL"),
                data: vec![0x42],
            };
            let mut client = NtlmOnlyNetworkClient;
            let result = client.send(&request).await;
            assert!(
                result.is_err(),
                "NtlmOnlyNetworkClient must refuse {protocol:?} requests \
                 (Kerberos is not supported; NTLM never calls the network client)"
            );
        }
    }

    /// Security posture of the connector configuration, pinned across
    /// version bumps: NLA (CredSSP) stays enforced, no bulk compression,
    /// no UDP sideband, no autologon, credentials mapped verbatim.
    #[test]
    fn test_connector_config_security_posture() {
        let config = build_connector_config(
            "alice".to_string(),
            "s3cret".to_string(),
            Some("CORP".to_string()),
            1280,
            720,
        );

        assert!(config.enable_credssp, "NLA/CredSSP must stay enabled");
        assert!(config.enable_tls, "TLS security protocol must stay enabled");
        assert!(!config.autologon, "autologon must stay disabled");
        assert!(
            config.compression_type.is_none(),
            "bulk compression must stay disabled (pre-0.17 behavior)"
        );
        assert!(
            config.multitransport_flags.is_none(),
            "UDP sideband transport must stay disabled"
        );
        match &config.credentials {
            Credentials::UsernamePassword { username, password } => {
                assert_eq!(username, "alice");
                assert_eq!(password, "s3cret");
            }
            other => panic!("credentials must be UsernamePassword, got {other:?}"),
        }
        assert_eq!(config.domain.as_deref(), Some("CORP"));
        assert_eq!(config.desktop_size.width, 1280);
        assert_eq!(config.desktop_size.height, 720);
        for flag in [
            PerformanceFlags::DISABLE_WALLPAPER,
            PerformanceFlags::DISABLE_THEMING,
            PerformanceFlags::DISABLE_CURSOR_SHADOW,
            PerformanceFlags::DISABLE_CURSORSETTINGS,
            PerformanceFlags::DISABLE_FULLWINDOWDRAG,
            PerformanceFlags::DISABLE_MENUANIMATIONS,
        ] {
            assert!(
                config.performance_flags.contains(flag),
                "performance flag {flag:?} must stay set"
            );
        }
    }

    // ========= Message-channel demux during finalize (licensing fix) =========
    //
    // IronRDP >= 0.17 requests the MCS message channel and advertises
    // network auto-detection, so the server may interleave auto-detect PDUs
    // with the licensing exchange. Without the demux, such a PDU is fed to
    // the license decoder and the connection dies with
    // `decode during SERVER_NEW_LICENSE/... decode error`.

    /// Wrap `user_data` in an MCS Send Data Indication on `channel_id`,
    /// X224-framed, exactly as received on the wire during finalize.
    fn encode_send_data_indication(channel_id: u16, user_data: &[u8]) -> Vec<u8> {
        let sdi = ironrdp::pdu::mcs::SendDataIndication {
            initiator_id: 1002,
            channel_id,
            user_data: std::borrow::Cow::Borrowed(user_data),
        };
        ironrdp::core::encode_vec(&ironrdp::pdu::x224::X224(sdi))
            .expect("encode SendDataIndication")
    }

    /// Encode a connect-time RTT Measure Request as sent by the server.
    fn encode_rtt_request(sequence_number: u16) -> Vec<u8> {
        use ironrdp::pdu::rdp::autodetect::{
            AutoDetectReqPdu, AutoDetectRequest, RTT_REQUEST_CONNECT_TIME,
        };
        let pdu = AutoDetectReqPdu::new(AutoDetectRequest::RttRequest {
            sequence_number,
            request_type: RTT_REQUEST_CONNECT_TIME,
        });
        ironrdp::core::encode_vec(&pdu).expect("encode AutoDetectReqPdu")
    }

    const MESSAGE_CHANNEL_ID: u16 = 1005;
    const IO_CHANNEL_ID: u16 = 1003;
    const USER_CHANNEL_ID: u16 = 1004;

    #[test]
    fn test_classify_without_message_channel_returns_none() {
        let pdu = encode_send_data_indication(MESSAGE_CHANNEL_ID, &encode_rtt_request(7));
        assert_eq!(classify_message_channel_pdu(&pdu, None), None);
    }

    #[test]
    fn test_classify_rtt_request_on_message_channel() {
        let pdu = encode_send_data_indication(MESSAGE_CHANNEL_ID, &encode_rtt_request(42));
        assert_eq!(
            classify_message_channel_pdu(&pdu, Some(MESSAGE_CHANNEL_ID)),
            Some(MessageChannelPdu::RttRequest {
                sequence_number: 42
            })
        );
    }

    /// A PDU on the I/O channel (licensing PDUs live there) must NEVER be
    /// classified as message-channel traffic: it has to reach the connector.
    #[test]
    fn test_classify_io_channel_pdu_returns_none() {
        let pdu = encode_send_data_indication(IO_CHANNEL_ID, &encode_rtt_request(7));
        assert_eq!(
            classify_message_channel_pdu(&pdu, Some(MESSAGE_CHANNEL_ID)),
            None
        );
    }

    /// A message-channel PDU that is not an auto-detect request (bandwidth
    /// stop, heartbeat, ...) is swallowed, never fed to the license decoder.
    #[test]
    fn test_classify_non_autodetect_message_channel_pdu_returns_other() {
        // 0x0080 = SEC_LICENSE_PKT-style header: not AUTODETECT_REQ.
        let user_data = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        let pdu = encode_send_data_indication(MESSAGE_CHANNEL_ID, &user_data);
        assert_eq!(
            classify_message_channel_pdu(&pdu, Some(MESSAGE_CHANNEL_ID)),
            Some(MessageChannelPdu::Other)
        );
    }

    #[test]
    fn test_classify_garbage_returns_none() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        assert_eq!(
            classify_message_channel_pdu(&garbage, Some(MESSAGE_CHANNEL_ID)),
            None
        );
    }

    /// Round-trip invariant: the encoded RTT response is a well-formed MCS
    /// Send Data Request on the message channel carrying an RTT Measure
    /// Response with the request's sequence number.
    #[test]
    fn test_encode_rtt_response_round_trip() {
        use ironrdp::pdu::mcs::McsMessage;
        use ironrdp::pdu::rdp::autodetect::{AutoDetectResponse, AutoDetectRspPdu};
        use ironrdp::pdu::x224::X224;

        let config =
            build_connector_config("alice".to_string(), "s3cret".to_string(), None, 1024, 768);
        let client_addr = "127.0.0.1:3389".parse().expect("addr");
        let mut connector = ClientConnector::new(config, client_addr);
        connector.message_channel_id = Some(MESSAGE_CHANNEL_ID);
        connector.state = ClientConnectorState::ConnectTimeAutoDetection {
            io_channel_id: IO_CHANNEL_ID,
            user_channel_id: USER_CHANNEL_ID,
        };

        let mut buf = WriteBuf::new();
        let len = encode_rtt_response(&connector, &mut buf, 42)
            .expect("encode must succeed")
            .expect("an RTT response must be produced");

        let mcs = ironrdp::core::decode::<X224<McsMessage<'_>>>(&buf[..len])
            .expect("response must be a valid X224/MCS PDU");
        let McsMessage::SendDataRequest(data) = mcs.0 else {
            panic!("response must be an MCS Send Data Request");
        };
        assert_eq!(data.channel_id, MESSAGE_CHANNEL_ID);
        assert_eq!(data.initiator_id, USER_CHANNEL_ID);

        let rsp = ironrdp::core::decode::<AutoDetectRspPdu>(&data.user_data)
            .expect("payload must be an AutoDetectRspPdu");
        assert_eq!(
            rsp.response,
            AutoDetectResponse::RttResponse {
                sequence_number: 42
            }
        );
    }

    /// Without a known user channel (or message channel), no response is
    /// emitted -- and no error either: the PDU is simply dropped.
    #[test]
    fn test_encode_rtt_response_without_channels_is_a_noop() {
        let config =
            build_connector_config("alice".to_string(), "s3cret".to_string(), None, 1024, 768);
        let client_addr = "127.0.0.1:3389".parse().expect("addr");
        let mut connector = ClientConnector::new(config, client_addr);

        let mut buf = WriteBuf::new();
        // No message channel negotiated.
        assert_eq!(
            encode_rtt_response(&connector, &mut buf, 1).expect("ok"),
            None
        );

        // Message channel known but connector in a phase without a user channel.
        connector.message_channel_id = Some(MESSAGE_CHANNEL_ID);
        assert_eq!(
            encode_rtt_response(&connector, &mut buf, 1).expect("ok"),
            None
        );
    }

    /// Source pin: the session path must go through the demuxed finalize,
    /// never through the upstream `ironrdp_tokio::connect_finalize` (which
    /// feeds interleaved message-channel PDUs to the license decoder).
    #[test]
    fn test_connect_uses_demuxed_finalize() {
        let source = include_str!("session.rs");
        assert!(
            source.contains("let connection_result = connect_finalize_with_message_channel_demux("),
            "connect() must use the demuxed finalize loop"
        );
        // Needle built at runtime so this pin does not match itself.
        let upstream_call = format!("ironrdp_tokio::{}(", "connect_finalize");
        assert!(
            !source.contains(&upstream_call),
            "the upstream connect_finalize must not be used anywhere"
        );
    }

    /// Source pin: inside the finalize step, every inbound PDU is classified
    /// BEFORE being fed to the connector, and message-channel PDUs return
    /// early (they never reach `connector.step`).
    #[test]
    fn test_finalize_step_demuxes_before_stepping() {
        let source = include_str!("session.rs");
        let fn_start = source
            .find("async fn finalize_step")
            .expect("finalize_step must exist");
        let body = &source[fn_start..];
        let classify_pos = body
            .find("classify_message_channel_pdu(&pdu, connector.message_channel_id)")
            .expect("finalize_step must classify each inbound PDU");
        let step_pos = body
            .find("None => connector.step(&pdu, buf)?")
            .expect("only unclassified PDUs may reach connector.step");
        assert!(
            classify_pos < step_pos,
            "classification must happen before connector.step"
        );

        let loop_start = source
            .find("async fn connect_finalize_with_message_channel_demux")
            .expect("demuxed finalize must exist");
        assert!(
            source[loop_start..].contains("finalize_step(&mut connector, framed, &mut buf)"),
            "the finalize loop must drive the demuxed finalize_step"
        );
    }

    /// Source pin (Kerberos phase A / point 7): the local `connect_begin`
    /// mirror sets the RESTRICTED_ADMIN_MODE_REQUIRED nego flag ONLY in
    /// Kerberos mode, and the connect() path uses the local mirror rather
    /// than the upstream `connect_begin`.
    #[test]
    fn test_connect_begin_sets_restricted_admin_flag_in_kerberos_mode() {
        let source = include_str!("session.rs");
        assert!(
            source.contains(
                "connect_begin_with_nego_flags(&mut framed, &mut connector, extra_nego_flags)"
            ),
            "connect() must drive the local connect_begin mirror"
        );
        // Needle built at runtime so this pin does not match itself. The
        // upstream connect_begin remains legitimate ONLY in the cert-fetch
        // TOFU path (no CredSSP, no nego flag needed): pin that the sole
        // occurrence lives after fetch_server_cert, i.e. outside connect().
        let upstream_call = format!("ironrdp_tokio::{}(&mut framed", "connect_begin");
        let occurrences: Vec<usize> = source
            .match_indices(&upstream_call)
            .map(|(i, _)| i)
            .collect();
        let fetch_start = source
            .find("async fn fetch_server_cert")
            .expect("fetch_server_cert must exist");
        assert!(
            occurrences.iter().all(|&i| i > fetch_start),
            "the upstream connect_begin is only allowed in the cert-fetch \
             (TOFU) path, never in the authenticated connect() path"
        );
        assert_eq!(
            occurrences.len(),
            1,
            "exactly one upstream connect_begin call (cert-fetch) is expected"
        );
        let sel_start = source
            .find("let extra_nego_flags = match config.auth_mode {")
            .expect("connect() must select nego flags from auth_mode");
        let sel = &source[sel_start..sel_start + 320];
        assert!(
            sel.contains("RdpAuthMode::Ntlm => nego::RequestFlags::empty()"),
            "NTLM mode must add no extra nego flag"
        );
        assert!(
            sel.contains("RESTRICTED_ADMIN_MODE_REQUIRED"),
            "Kerberos mode must set RESTRICTED_ADMIN_MODE_REQUIRED"
        );
    }

    /// Source pin (Kerberos phase A / point 7): the local CredSSP mirror
    /// uses `CredentialLess` + a Kerberos-only package list in Restricted
    /// Admin mode, and keeps `WithCredentials` + NTLM otherwise.
    #[test]
    fn test_credssp_uses_credentialless_in_kerberos_mode() {
        let source = include_str!("session.rs");
        let fn_start = source
            .find("impl LocalCredsspSequence {")
            .expect("LocalCredsspSequence must exist");
        let body = &source[fn_start..];
        assert!(
            body.contains("RdpAuthMode::Ntlm => (")
                && body.contains("CredSspMode::WithCredentials")
                && body.contains("ClientMode::Ntlm"),
            "NTLM mode must keep WithCredentials + ClientMode::Ntlm"
        );
        assert!(
            body.contains("CredSspMode::CredentialLess"),
            "Kerberos mode must use CredentialLess (Restricted Admin)"
        );
        assert!(
            body.contains("package_list: Some(\"kerberos\".to_owned())"),
            "Kerberos mode must fail-closed to the kerberos package (no NTLM downgrade)"
        );
    }

    /// Source pin: the Kerberos relay NetworkClient refuses every non-TCP
    /// transport fail-closed.
    #[test]
    fn test_kerberos_relay_refuses_non_tcp() {
        let source = include_str!("session.rs");
        let fn_start = source
            .find("impl NetworkClient for KerberosRelayNetworkClient")
            .expect("KerberosRelayNetworkClient must impl NetworkClient");
        let body = &source[fn_start..fn_start + 900];
        assert!(
            body.contains("NetworkProtocol::Udp | NetworkProtocol::Http | NetworkProtocol::Https"),
            "the relay must explicitly refuse Udp/Http/Https"
        );
    }

    /// Noop cache mirroring the upstream private `NoopLicenseCache`, used to
    /// build a `LicenseExchangeSequence` in tests.
    #[derive(Debug)]
    struct TestNoopLicenseCache;

    impl ironrdp::connector::LicenseCache for TestNoopLicenseCache {
        fn get_license(
            &self,
            _license_info: ironrdp::pdu::rdp::server_license::LicenseInformation,
        ) -> ConnectorResult<Option<Vec<u8>>> {
            Ok(None)
        }

        fn store_license(
            &self,
            _license_info: ironrdp::pdu::rdp::server_license::LicenseInformation,
        ) -> ConnectorResult<()> {
            Ok(())
        }
    }

    /// Build a connector frozen mid-licensing with a negotiated message
    /// channel -- the exact production state in which the regression fired.
    fn connector_in_licensing_exchange() -> ClientConnector {
        let config =
            build_connector_config("alice".to_string(), "s3cret".to_string(), None, 1024, 768);
        let client_addr = "127.0.0.1:3389".parse().expect("addr");
        let mut connector = ClientConnector::new(config, client_addr);
        connector.message_channel_id = Some(MESSAGE_CHANNEL_ID);
        connector.state = ClientConnectorState::LicensingExchange {
            io_channel_id: IO_CHANNEL_ID,
            user_channel_id: USER_CHANNEL_ID,
            license_exchange: ironrdp::connector::LicenseExchangeSequence::new(
                IO_CHANNEL_ID,
                "alice".to_string(),
                None,
                [0u32; 4],
                std::sync::Arc::new(TestNoopLicenseCache),
            ),
        };
        connector
    }

    /// Server License Error PDU "Valid Client" on the I/O channel: what a
    /// standard Windows host sends to complete the licensing exchange.
    fn encode_valid_client_license_pdu() -> Vec<u8> {
        use ironrdp::pdu::rdp::server_license::{LicensePdu, LicensingErrorMessage};
        let msg = LicensingErrorMessage::new_valid_client().expect("valid client message");
        let user_data =
            ironrdp::core::encode_vec(&LicensePdu::from(msg)).expect("encode LicensePdu");
        encode_send_data_indication(IO_CHANNEL_ID, &user_data)
    }

    /// Battle-tested counterfactual: pin the UPSTREAM gap that motivates the
    /// demux. Feeding an auto-detect PDU to the connector mid-licensing must
    /// error out (the production `SERVER_NEW_LICENSE ... decode error`). The
    /// day upstream demuxes message-channel PDUs during licensing, this test
    /// fails and tells us the local workaround can be retired.
    #[test]
    fn test_upstream_connector_chokes_on_interleaved_autodetect_without_demux() {
        let mut connector = connector_in_licensing_exchange();
        let rtt_pdu = encode_send_data_indication(MESSAGE_CHANNEL_ID, &encode_rtt_request(7));

        let mut buf = WriteBuf::new();
        let result = connector.step(&rtt_pdu, &mut buf);
        assert!(
            result.is_err(),
            "upstream connector is expected to reject an interleaved auto-detect PDU \
             during licensing; if this now succeeds, the demux workaround can be removed"
        );
    }

    /// Sanity check of the counterfactual: the SAME connector state accepts
    /// the legitimate licensing PDU, so the failure above is caused by the
    /// interleaved PDU, not by a malformed test fixture.
    #[test]
    fn test_upstream_connector_accepts_licensing_pdu_in_same_state() {
        let mut connector = connector_in_licensing_exchange();
        let mut buf = WriteBuf::new();
        connector
            .step(&encode_valid_client_license_pdu(), &mut buf)
            .expect("valid client licensing PDU must be accepted");
        assert!(
            matches!(
                connector.state,
                ClientConnectorState::MultitransportBootstrapping { .. }
            ),
            "licensing must complete and transition past LicensingExchange"
        );
    }

    /// E2E replay of the production failure over a real (in-memory) duplex
    /// transport: the server interleaves an RTT Measure Request on the
    /// message channel in the middle of the licensing exchange, then
    /// completes licensing on the I/O channel. Pre-fix, step 1 aborted the
    /// connection with the license decode error. Post-fix, the RTT request
    /// is answered on the wire and licensing completes.
    #[tokio::test]
    async fn test_e2e_interleaved_rtt_during_licensing_is_answered_and_licensing_completes() {
        use ironrdp::pdu::mcs::McsMessage;
        use ironrdp::pdu::rdp::autodetect::{AutoDetectResponse, AutoDetectRspPdu};
        use ironrdp::pdu::x224::X224;
        use tokio::io::AsyncWriteExt as _;

        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
        let mut connector = connector_in_licensing_exchange();
        let mut buf = WriteBuf::new();

        // The scripted server interleaves auto-detect with licensing.
        server_side
            .write_all(&encode_send_data_indication(
                MESSAGE_CHANNEL_ID,
                &encode_rtt_request(42),
            ))
            .await
            .expect("server writes RTT request");
        server_side
            .write_all(&encode_valid_client_license_pdu())
            .await
            .expect("server writes licensing PDU");

        // Step 1: the RTT request is answered, NOT fed to the connector.
        let outcome = finalize_step(&mut connector, &mut framed, &mut buf)
            .await
            .expect("interleaved RTT request must not abort the connection");
        assert_eq!(outcome, FinalizeStepOutcome::AnsweredRtt);
        assert!(
            matches!(
                connector.state,
                ClientConnectorState::LicensingExchange { .. }
            ),
            "the connector must still be mid-licensing after the RTT detour"
        );

        // The RTT response must be on the wire: an MCS Send Data Request on
        // the message channel echoing the sequence number.
        let frame = read_tpkt_frame(&mut server_side).await;
        let mcs = ironrdp::core::decode::<X224<McsMessage<'_>>>(&frame)
            .expect("RTT response must be a valid X224/MCS PDU");
        let McsMessage::SendDataRequest(data) = mcs.0 else {
            panic!("RTT response must be an MCS Send Data Request");
        };
        assert_eq!(data.channel_id, MESSAGE_CHANNEL_ID);
        let rsp = ironrdp::core::decode::<AutoDetectRspPdu>(&data.user_data)
            .expect("payload must be an AutoDetectRspPdu");
        assert_eq!(
            rsp.response,
            AutoDetectResponse::RttResponse {
                sequence_number: 42
            }
        );

        // Step 2: the licensing PDU reaches the connector and completes the
        // licensing exchange.
        let outcome = finalize_step(&mut connector, &mut framed, &mut buf)
            .await
            .expect("licensing PDU must be accepted");
        assert_eq!(outcome, FinalizeStepOutcome::SteppedConnector);
        assert!(
            matches!(
                connector.state,
                ClientConnectorState::MultitransportBootstrapping { .. }
            ),
            "licensing must complete after the interleaved detour"
        );
    }

    /// E2E: a non-RTT message-channel PDU (e.g. a bandwidth measure payload)
    /// is swallowed without a reply and without aborting the sequence.
    #[tokio::test]
    async fn test_e2e_non_rtt_message_channel_pdu_is_swallowed() {
        use tokio::io::AsyncWriteExt as _;

        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
        let mut connector = connector_in_licensing_exchange();
        let mut buf = WriteBuf::new();

        let non_autodetect = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
        server_side
            .write_all(&encode_send_data_indication(
                MESSAGE_CHANNEL_ID,
                &non_autodetect,
            ))
            .await
            .expect("server writes message-channel PDU");
        server_side
            .write_all(&encode_valid_client_license_pdu())
            .await
            .expect("server writes licensing PDU");

        let outcome = finalize_step(&mut connector, &mut framed, &mut buf)
            .await
            .expect("message-channel PDU must not abort the connection");
        assert_eq!(outcome, FinalizeStepOutcome::IgnoredMessageChannelPdu);

        let outcome = finalize_step(&mut connector, &mut framed, &mut buf)
            .await
            .expect("licensing PDU must be accepted");
        assert_eq!(outcome, FinalizeStepOutcome::SteppedConnector);
        assert!(matches!(
            connector.state,
            ClientConnectorState::MultitransportBootstrapping { .. }
        ));
    }

    // ========= Message-channel demux invariants (property-based) =========

    mod demux_invariants {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Total function: NO byte sequence may panic the classifier
            /// (it sits on the wire path, fed with attacker-controlled data).
            #[test]
            fn classifier_never_panics_on_arbitrary_bytes(
                bytes in proptest::collection::vec(any::<u8>(), 0..128),
                channel in proptest::option::of(any::<u16>()),
            ) {
                let _ = classify_message_channel_pdu(&bytes, channel);
            }

            /// Every RTT request on the message channel is intercepted, for
            /// ANY channel id and ANY sequence number.
            #[test]
            fn rtt_request_on_message_channel_is_always_intercepted(
                msg_channel in any::<u16>(),
                sequence_number in any::<u16>(),
            ) {
                let pdu = encode_send_data_indication(
                    msg_channel,
                    &encode_rtt_request(sequence_number),
                );
                prop_assert_eq!(
                    classify_message_channel_pdu(&pdu, Some(msg_channel)),
                    Some(MessageChannelPdu::RttRequest { sequence_number })
                );
            }

            /// A PDU on ANY other channel is NEVER intercepted, whatever its
            /// payload: licensing traffic cannot be swallowed by the demux.
            #[test]
            fn pdu_on_other_channel_is_never_intercepted(
                channel in any::<u16>(),
                msg_channel in any::<u16>(),
                payload in proptest::collection::vec(any::<u8>(), 0..64),
            ) {
                prop_assume!(channel != msg_channel);
                let pdu = encode_send_data_indication(channel, &payload);
                prop_assert_eq!(
                    classify_message_channel_pdu(&pdu, Some(msg_channel)),
                    None
                );
            }

            /// The RTT response round-trips for ANY sequence number: what we
            /// put on the wire is always a well-formed response the server
            /// can correlate with its request.
            #[test]
            fn rtt_response_round_trips_for_any_sequence_number(
                sequence_number in any::<u16>(),
            ) {
                use ironrdp::pdu::mcs::McsMessage;
                use ironrdp::pdu::rdp::autodetect::{AutoDetectResponse, AutoDetectRspPdu};
                use ironrdp::pdu::x224::X224;

                let mut connector = connector_in_licensing_exchange();
                connector.state = ClientConnectorState::ConnectTimeAutoDetection {
                    io_channel_id: IO_CHANNEL_ID,
                    user_channel_id: USER_CHANNEL_ID,
                };

                let mut buf = WriteBuf::new();
                let len = encode_rtt_response(&connector, &mut buf, sequence_number)
                    .expect("encode must succeed")
                    .expect("an RTT response must be produced");

                let mcs = ironrdp::core::decode::<X224<McsMessage<'_>>>(&buf[..len])
                    .expect("must decode");
                let McsMessage::SendDataRequest(data) = mcs.0 else {
                    panic!("must be a Send Data Request");
                };
                prop_assert_eq!(data.channel_id, MESSAGE_CHANNEL_ID);
                prop_assert_eq!(data.initiator_id, USER_CHANNEL_ID);
                let rsp = ironrdp::core::decode::<AutoDetectRspPdu>(&data.user_data)
                    .expect("must be an AutoDetectRspPdu");
                prop_assert_eq!(
                    rsp.response,
                    AutoDetectResponse::RttResponse { sequence_number }
                );
            }
        }
    }

    // ========= Deactivation-Reactivation (battle-tested + E2E) =========
    //
    // The IronRDP 0.17 migration rewrote the DeactivateAll handler around
    // `ConnectionActivationFactory`. These tests drive the REAL
    // `drive_reactivation` code over an in-memory transport against a
    // scripted server, asserting both the negotiated outcome and the
    // client PDUs actually put on the wire.

    const REACTIVATION_SHARE_ID: u32 = 0x0011_66EA;

    fn test_activation_factory() -> ConnectionActivationFactory {
        ConnectionActivationFactory::new(
            build_connector_config("alice".to_string(), "s3cret".to_string(), None, 1024, 768),
            IO_CHANNEL_ID,
            USER_CHANNEL_ID,
        )
    }

    /// Read one TPKT-framed PDU from the scripted server side.
    async fn read_tpkt_frame(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt as _;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.expect("TPKT header");
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut frame = vec![0u8; len];
        frame[..4].copy_from_slice(&header);
        stream.read_exact(&mut frame[4..]).await.expect("TPKT body");
        frame
    }

    /// Wrap a Share Control PDU the way the server does: Share Control
    /// header inside an MCS Send Data Indication on the I/O channel.
    fn encode_server_share_control(
        share_id: u32,
        pdu: ironrdp::pdu::rdp::headers::ShareControlPdu,
    ) -> Vec<u8> {
        use ironrdp::pdu::rdp::capability_sets::SERVER_CHANNEL_ID;
        let header = ironrdp::pdu::rdp::headers::ShareControlHeader {
            share_control_pdu: pdu,
            pdu_source: SERVER_CHANNEL_ID,
            share_id,
        };
        let user_data = ironrdp::core::encode_vec(&header).expect("encode ShareControlHeader");
        encode_send_data_indication(IO_CHANNEL_ID, &user_data)
    }

    /// Server Demand Active PDU advertising the (renegotiated) desktop size
    /// via a Bitmap capability set.
    fn encode_server_demand_active(share_id: u32, width: u16, height: u16) -> Vec<u8> {
        use ironrdp::pdu::rdp::capability_sets::{
            Bitmap, BitmapDrawingFlags, CapabilitySet, DemandActive, ServerDemandActive,
        };
        use ironrdp::pdu::rdp::headers::ShareControlPdu;
        let demand = ServerDemandActive {
            pdu: DemandActive {
                source_descriptor: "RDP".to_owned(),
                capability_sets: vec![CapabilitySet::Bitmap(Bitmap {
                    pref_bits_per_pix: 32,
                    desktop_width: width,
                    desktop_height: height,
                    desktop_resize_flag: true,
                    drawing_flags: BitmapDrawingFlags::empty(),
                })],
            },
        };
        encode_server_share_control(share_id, ShareControlPdu::ServerDemandActive(demand))
    }

    fn encode_server_share_data(
        share_id: u32,
        pdu: ironrdp::pdu::rdp::headers::ShareDataPdu,
    ) -> Vec<u8> {
        use ironrdp::pdu::rdp::client_info::CompressionType;
        use ironrdp::pdu::rdp::headers::{
            CompressionFlags, ShareControlPdu, ShareDataHeader, StreamPriority,
        };
        let header = ShareDataHeader {
            share_data_pdu: pdu,
            stream_priority: StreamPriority::Medium,
            compression_flags: CompressionFlags::empty(),
            compression_type: CompressionType::K8,
        };
        encode_server_share_control(share_id, ShareControlPdu::Data(header))
    }

    fn encode_server_font_map(share_id: u32) -> Vec<u8> {
        use ironrdp::pdu::rdp::finalization_messages::FontPdu;
        use ironrdp::pdu::rdp::headers::ShareDataPdu;
        encode_server_share_data(share_id, ShareDataPdu::FontMap(FontPdu::default()))
    }

    /// Decode a client->server frame: MCS Send Data Request carrying a
    /// Share Control header. Returns (mcs_channel_id, share_id, pdu).
    fn decode_client_share_control(
        frame: &[u8],
    ) -> (u16, u32, ironrdp::pdu::rdp::headers::ShareControlPdu) {
        use ironrdp::pdu::mcs::McsMessage;
        use ironrdp::pdu::x224::X224;
        let mcs = ironrdp::core::decode::<X224<McsMessage<'_>>>(frame).expect("X224/MCS");
        let McsMessage::SendDataRequest(data) = mcs.0 else {
            panic!("client frame must be an MCS Send Data Request");
        };
        let header = ironrdp::core::decode::<ironrdp::pdu::rdp::headers::ShareControlHeader>(
            &data.user_data,
        )
        .expect("ShareControlHeader");
        (data.channel_id, header.share_id, header.share_control_pdu)
    }

    /// E2E: full Deactivation-Reactivation over an in-memory transport. The
    /// scripted server demands activation with a NEW desktop size and plays
    /// the complete finalization handshake. Asserts BOTH directions: the
    /// negotiated outcome AND the client PDUs on the wire (Confirm Active
    /// echoing the negotiated size, then Synchronize, Control Cooperate,
    /// Request Control, Font List in the spec-mandated order,
    /// [MS-RDPBCGR] 1.3.1.3).
    #[tokio::test]
    async fn test_e2e_reactivation_completes_and_negotiates_desktop_size() {
        use ironrdp::pdu::rdp::capability_sets::{CapabilitySet, SERVER_CHANNEL_ID};
        use ironrdp::pdu::rdp::finalization_messages::{ControlAction, ControlPdu, SynchronizePdu};
        use ironrdp::pdu::rdp::headers::{ShareControlPdu, ShareDataPdu};
        use tokio::io::AsyncWriteExt as _;

        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
        let factory = test_activation_factory();

        server_side
            .write_all(&encode_server_demand_active(
                REACTIVATION_SHARE_ID,
                1680,
                1050,
            ))
            .await
            .expect("demand active");
        server_side
            .write_all(&encode_server_share_data(
                REACTIVATION_SHARE_ID,
                ShareDataPdu::Synchronize(SynchronizePdu {
                    target_user_id: USER_CHANNEL_ID,
                }),
            ))
            .await
            .expect("synchronize");
        server_side
            .write_all(&encode_server_share_data(
                REACTIVATION_SHARE_ID,
                ShareDataPdu::Control(ControlPdu {
                    action: ControlAction::Cooperate,
                    grant_id: 0,
                    control_id: 0,
                }),
            ))
            .await
            .expect("cooperate");
        server_side
            .write_all(&encode_server_share_data(
                REACTIVATION_SHARE_ID,
                ShareDataPdu::Control(ControlPdu {
                    action: ControlAction::GrantedControl,
                    grant_id: USER_CHANNEL_ID,
                    control_id: u32::from(SERVER_CHANNEL_ID),
                }),
            ))
            .await
            .expect("granted control");
        server_side
            .write_all(&encode_server_font_map(REACTIVATION_SHARE_ID))
            .await
            .expect("font map");

        let outcome = drive_reactivation(&factory, &mut framed)
            .await
            .expect("reactivation must complete");

        assert_eq!(outcome.desktop_size.width, 1680);
        assert_eq!(outcome.desktop_size.height, 1050);
        assert_eq!(outcome.share_id, REACTIVATION_SHARE_ID);
        assert_eq!(
            outcome.io_channel_id, IO_CHANNEL_ID,
            "MCS channel ids are invariant across reactivation"
        );
        assert_eq!(
            outcome.user_channel_id, USER_CHANNEL_ID,
            "MCS channel ids are invariant across reactivation"
        );

        // Wire, client direction, frame 1: Confirm Active echoing the size.
        let frame = read_tpkt_frame(&mut server_side).await;
        let (channel, share_id, pdu) = decode_client_share_control(&frame);
        assert_eq!(channel, IO_CHANNEL_ID);
        assert_eq!(
            share_id, REACTIVATION_SHARE_ID,
            "Confirm Active must echo the server's share id"
        );
        let ShareControlPdu::ClientConfirmActive(confirm) = pdu else {
            panic!("first client frame must be Client Confirm Active");
        };
        let bitmap = confirm
            .pdu
            .capability_sets
            .iter()
            .find_map(|c| match c {
                CapabilitySet::Bitmap(b) => Some(b),
                _ => None,
            })
            .expect("Confirm Active must carry a Bitmap capability set");
        assert_eq!(bitmap.desktop_width, 1680);
        assert_eq!(bitmap.desktop_height, 1050);

        // Frames 2-5: finalization PDUs in the spec-mandated order.
        let mut kinds = Vec::new();
        for _ in 0..4 {
            let frame = read_tpkt_frame(&mut server_side).await;
            let (_, _, pdu) = decode_client_share_control(&frame);
            let ShareControlPdu::Data(data) = pdu else {
                panic!("finalization frames must be Share Data PDUs");
            };
            kinds.push(match data.share_data_pdu {
                ShareDataPdu::Synchronize(_) => "Synchronize",
                ShareDataPdu::Control(ControlPdu {
                    action: ControlAction::Cooperate,
                    ..
                }) => "ControlCooperate",
                ShareDataPdu::Control(ControlPdu {
                    action: ControlAction::RequestControl,
                    ..
                }) => "RequestControl",
                ShareDataPdu::FontList(_) => "FontList",
                other => panic!("unexpected finalization PDU: {other:?}"),
            });
        }
        assert_eq!(
            kinds,
            [
                "Synchronize",
                "ControlCooperate",
                "RequestControl",
                "FontList"
            ]
        );
    }

    /// E2E, battle-tested quirk: some servers (GNOME Remote Desktop) send a
    /// Server Deactivate All PDU BEFORE Demand Active inside the sequence.
    /// The reactivation must skip it and still finalize -- pins the upstream
    /// tolerance our handler relies on.
    #[tokio::test]
    async fn test_e2e_reactivation_tolerates_deactivate_all_before_demand_active() {
        use ironrdp::pdu::rdp::headers::{ServerDeactivateAll, ShareControlPdu};
        use tokio::io::AsyncWriteExt as _;

        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
        let factory = test_activation_factory();

        server_side
            .write_all(&encode_server_share_control(
                REACTIVATION_SHARE_ID,
                ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll),
            ))
            .await
            .expect("deactivate all");
        server_side
            .write_all(&encode_server_demand_active(
                REACTIVATION_SHARE_ID,
                800,
                600,
            ))
            .await
            .expect("demand active");
        server_side
            .write_all(&encode_server_font_map(REACTIVATION_SHARE_ID))
            .await
            .expect("font map");

        let outcome = drive_reactivation(&factory, &mut framed)
            .await
            .expect("reactivation must tolerate DeactivateAll before DemandActive");
        assert_eq!(outcome.desktop_size.width, 800);
        assert_eq!(outcome.desktop_size.height, 600);
    }

    /// E2E: an unexpected PDU where Demand Active is required fails cleanly
    /// (no hang, no panic): the session tears down instead of spinning.
    #[tokio::test]
    async fn test_e2e_reactivation_fails_cleanly_on_unexpected_pdu() {
        use tokio::io::AsyncWriteExt as _;

        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
        let factory = test_activation_factory();

        // A Font Map where a Demand Active is required.
        server_side
            .write_all(&encode_server_font_map(REACTIVATION_SHARE_ID))
            .await
            .expect("font map");

        let result = drive_reactivation(&factory, &mut framed).await;
        assert!(
            result.is_err(),
            "unexpected PDU must abort the reactivation, not hang"
        );
    }

    // ====== Deactivation-Reactivation invariants (property-based) ======

    mod reactivation_invariants {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            /// For ANY desktop size and share id demanded by the server,
            /// the finalized outcome reports exactly the negotiated values
            /// and the invariant MCS channel ids. Drives the REAL
            /// `drive_reactivation` over an in-memory transport per case.
            #[test]
            fn reactivation_outcome_matches_server_negotiation(
                width in any::<u16>(),
                height in any::<u16>(),
                share_id in any::<u32>(),
            ) {
                use tokio::io::AsyncWriteExt as _;

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");

                rt.block_on(async {
                    let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
                    let mut framed = ironrdp_tokio::TokioFramed::new(client_side);
                    let factory = test_activation_factory();

                    server_side
                        .write_all(&encode_server_demand_active(share_id, width, height))
                        .await
                        .expect("demand active");
                    server_side
                        .write_all(&encode_server_font_map(share_id))
                        .await
                        .expect("font map");

                    let outcome = drive_reactivation(&factory, &mut framed)
                        .await
                        .expect("reactivation must complete");

                    prop_assert_eq!(outcome.desktop_size.width, width);
                    prop_assert_eq!(outcome.desktop_size.height, height);
                    prop_assert_eq!(outcome.share_id, share_id);
                    prop_assert_eq!(outcome.io_channel_id, IO_CHANNEL_ID);
                    prop_assert_eq!(outcome.user_channel_id, USER_CHANNEL_ID);
                    Ok(())
                })?;
            }

            /// The dimensions forwarded to the encoder and the web after a
            /// reactivation are ALWAYS even (H.264 YUV 4:2:0) and within one
            /// pixel of the negotiated value -- and `align_even` is total on
            /// all of `u16` (a hostile server must not be able to panic the
            /// session task with `width = u16::MAX`).
            #[test]
            fn aligned_dimensions_are_always_even_and_close(v in any::<u16>()) {
                let aligned = align_even(v);
                prop_assert_eq!(aligned % 2, 0);
                prop_assert!(aligned.abs_diff(v) <= 1);
            }
        }
    }

    // ============ Input pipeline invariants (property-based) ============
    //
    // These pin the stuck-modifier fix against regression for ANY input
    // sequence, not just the scenarios enumerated above. They live here
    // (not in tests/) because the crate is a binary: integration tests
    // cannot import handle_input_event / LockSyncState.

    mod input_invariants {
        use proptest::prelude::*;

        use super::*;

        /// Mix of JS codes the frontend actually sends (valid mappings,
        /// modifiers, extended keys) and arbitrary garbage.
        fn arb_js_code() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("KeyA".to_owned()),
                Just("ShiftLeft".to_owned()),
                Just("ControlLeft".to_owned()),
                Just("ArrowUp".to_owned()),
                Just("CapsLock".to_owned()),
                "[a-zA-Z0-9]{0,12}",
            ]
        }

        fn arb_input_event() -> impl Strategy<Value = RdpInputEvent> {
            prop_oneof![
                any::<u16>().prop_map(|scancode| RdpInputEvent::KeyPressed { scancode }),
                any::<u16>().prop_map(|scancode| RdpInputEvent::KeyReleased { scancode }),
                (any::<u16>(), any::<u16>()).prop_map(|(x, y)| RdpInputEvent::MouseMove { x, y }),
                any::<u8>().prop_map(|button| RdpInputEvent::MouseButtonPressed { button }),
                any::<u8>().prop_map(|button| RdpInputEvent::MouseButtonReleased { button }),
                (any::<bool>(), any::<i16>())
                    .prop_map(|(vertical, amount)| RdpInputEvent::WheelScroll { vertical, amount }),
                (any::<u8>(), any::<bool>(), any::<u16>(), any::<u16>()).prop_map(
                    |(button, pressed, x, y)| RdpInputEvent::MouseButton {
                        button,
                        pressed,
                        x,
                        y
                    }
                ),
                (any::<i16>(), any::<i16>())
                    .prop_map(|(delta_x, delta_y)| RdpInputEvent::MouseWheel { delta_x, delta_y }),
                (
                    arb_js_code(),
                    any::<bool>(),
                    any::<bool>(),
                    any::<bool>(),
                    any::<bool>()
                )
                    .prop_map(|(code, pressed, caps, num, scroll)| {
                        keyboard_event_with_locks(&code, &code, pressed, caps, num, scroll)
                    }),
                Just(RdpInputEvent::ReleaseAll),
            ]
        }

        proptest! {
            /// I1 + I2 - total release and idempotence: after ReleaseAll,
            /// no key or mouse button stays pressed in the input database,
            /// and an immediate second ReleaseAll emits no event.
            #[test]
            fn prop_release_all_clears_all_state(
                events in proptest::collection::vec(arb_input_event(), 0..64)
            ) {
                let mut db = InputDatabase::new();
                let mut locks = LockSyncState::default();
                for event in events {
                    let _ = handle_input_event(&mut db, &mut locks, event);
                }

                let _ = handle_input_event(&mut db, &mut locks, RdpInputEvent::ReleaseAll);
                prop_assert!(
                    !db.keyboard_state().any(),
                    "keys still pressed after ReleaseAll"
                );
                prop_assert!(
                    !db.mouse_buttons_state().any(),
                    "mouse buttons still pressed after ReleaseAll"
                );

                let again = handle_input_event(&mut db, &mut locks, RdpInputEvent::ReleaseAll);
                prop_assert!(again.is_empty(), "ReleaseAll must be idempotent");
            }

            /// I3 - no panic: the input pipeline accepts ANY event sequence
            /// (garbage JS codes, out-of-range buttons, extreme deltas)
            /// without panicking.
            #[test]
            fn prop_handle_input_never_panics(
                events in proptest::collection::vec(arb_input_event(), 0..64)
            ) {
                let mut db = InputDatabase::new();
                let mut locks = LockSyncState::default();
                for event in events {
                    let _ = handle_input_event(&mut db, &mut locks, event);
                }
            }

            /// I4 - minimal synchronization: exactly one SynchronizeEvent
            /// per lock-state transition, never two for the same state.
            #[test]
            fn prop_lock_sync_is_minimal(
                lock_states in proptest::collection::vec(
                    (any::<bool>(), any::<bool>(), any::<bool>()),
                    1..32
                )
            ) {
                let mut db = InputDatabase::new();
                let mut locks = LockSyncState::default();
                let mut last: Option<(bool, bool, bool)> = None;
                let mut expected = 0usize;
                let mut emitted = 0usize;

                for (caps, num, scroll) in lock_states {
                    if last != Some((caps, num, scroll)) {
                        expected += 1;
                        last = Some((caps, num, scroll));
                    }
                    let events = handle_input_event(
                        &mut db,
                        &mut locks,
                        keyboard_event_with_locks("KeyA", "a", true, caps, num, scroll),
                    );
                    emitted += events
                        .iter()
                        .filter(|e| matches!(e, FastPathInputEvent::SyncEvent(_)))
                        .count();
                }

                prop_assert_eq!(emitted, expected);
            }
        }
    }

    #[test]
    fn test_translate_key_released() {
        let ops = translate_input_event(RdpInputEvent::KeyReleased { scancode: 0x1E });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_mouse_move() {
        let ops = translate_input_event(RdpInputEvent::MouseMove { x: 100, y: 200 });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_mouse_button_pressed() {
        let ops = translate_input_event(RdpInputEvent::MouseButtonPressed { button: 0 });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_mouse_button_released() {
        let ops = translate_input_event(RdpInputEvent::MouseButtonReleased { button: 2 });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_mouse_button_invalid_returns_empty() {
        let ops = translate_input_event(RdpInputEvent::MouseButtonPressed { button: 255 });
        assert!(ops.is_empty());
    }

    #[test]
    fn test_translate_wheel_scroll() {
        let ops = translate_input_event(RdpInputEvent::WheelScroll {
            vertical: true,
            amount: 120,
        });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_mouse_button() {
        let ops = translate_input_event(RdpInputEvent::MouseButton {
            button: 0,
            pressed: true,
            x: 50,
            y: 60,
        });
        assert_eq!(ops.len(), 2); // MouseMove + MouseButtonPressed
    }

    #[test]
    fn test_translate_high_level_mouse_button_release() {
        let ops = translate_input_event(RdpInputEvent::MouseButton {
            button: 2,
            pressed: false,
            x: 50,
            y: 60,
        });
        assert_eq!(ops.len(), 2); // MouseMove + MouseButtonReleased
    }

    #[test]
    fn test_translate_high_level_mouse_button_invalid() {
        let ops = translate_input_event(RdpInputEvent::MouseButton {
            button: 255,
            pressed: true,
            x: 0,
            y: 0,
        });
        assert!(ops.is_empty());
    }

    #[test]
    fn test_translate_high_level_mouse_wheel_vertical() {
        let ops = translate_input_event(RdpInputEvent::MouseWheel {
            delta_x: 0,
            delta_y: -120,
        });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_mouse_wheel_horizontal() {
        let ops = translate_input_event(RdpInputEvent::MouseWheel {
            delta_x: 100,
            delta_y: 0,
        });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_mouse_wheel_both() {
        let ops = translate_input_event(RdpInputEvent::MouseWheel {
            delta_x: 50,
            delta_y: -120,
        });
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn test_translate_high_level_mouse_wheel_zero() {
        let ops = translate_input_event(RdpInputEvent::MouseWheel {
            delta_x: 0,
            delta_y: 0,
        });
        assert!(ops.is_empty());
    }

    #[test]
    fn test_translate_high_level_keyboard_known_key() {
        let ops = translate_input_event(keyboard_event("KeyA", "a", true));
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_release() {
        let ops = translate_input_event(keyboard_event("KeyA", "a", false));
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_unknown_key() {
        let ops = translate_input_event(keyboard_event("UnknownKey", "?", true));
        assert!(ops.is_empty());
    }

    #[test]
    fn test_translate_extended_key() {
        let ops = translate_input_event(RdpInputEvent::KeyPressed { scancode: 0xE048 });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_extended_key() {
        let ops = translate_input_event(keyboard_event("ArrowUp", "ArrowUp", true));
        assert_eq!(ops.len(), 1);
    }

    // ==================== encode_region_as_png Tests ====================

    #[test]
    fn test_encode_region_as_png_produces_valid_png() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 64, 64);
        let png = encode_region_as_png(&image, 0, 0, 64, 64).unwrap();
        assert!(png.len() > 8, "PNG should have header + data");
        assert_eq!(&png[0..4], &[0x89, b'P', b'N', b'G'], "PNG magic bytes");
    }

    #[test]
    fn test_encode_region_as_png_correct_dimensions() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 4, 4);
        let png = encode_region_as_png(&image, 1, 1, 2, 2).unwrap();
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 2);
        assert_eq!(decoded.height(), 2);
    }

    #[test]
    fn test_encode_region_as_png_full_screen() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 1280, 720);
        let png = encode_region_as_png(&image, 0, 0, 1280, 720).unwrap();
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 1280);
        assert_eq!(decoded.height(), 720);
    }

    #[test]
    fn test_encode_region_as_png_single_row() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 1280, 720);
        let png = encode_region_as_png(&image, 0, 0, 1280, 1).unwrap();
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 1280);
        assert_eq!(decoded.height(), 1);
    }

    #[test]
    fn test_encode_region_as_png_single_pixel() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 10, 10);
        let png = encode_region_as_png(&image, 5, 3, 1, 1).unwrap();
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 1);
        assert_eq!(decoded.height(), 1);
    }

    #[test]
    fn test_encode_region_as_png_rgb_strip_alpha() {
        // Manually verify the RGB extraction logic: an RGBx32 buffer with
        // alpha=0 must produce an opaque RGB PNG.
        let w: u32 = 2;
        let h: u32 = 2;
        // Simulate what encode_region_as_png does: strip alpha from RGBA
        let rgba_fb: Vec<u8> = vec![
            255, 0, 0, 0, // red, alpha=0
            0, 255, 0, 0, // green, alpha=0
            0, 0, 255, 0, // blue, alpha=0
            255, 255, 255, 0, // white, alpha=0
        ];
        let mut rgb_buf = Vec::with_capacity((w * h * 3) as usize);
        for pixel in rgba_fb.chunks_exact(4) {
            rgb_buf.push(pixel[0]);
            rgb_buf.push(pixel[1]);
            rgb_buf.push(pixel[2]);
        }

        let mut png_data = Vec::new();
        PngEncoder::new(&mut png_data)
            .write_image(&rgb_buf, w, h, ExtendedColorType::Rgb8)
            .unwrap();

        let decoder = image::ImageReader::new(std::io::Cursor::new(&png_data))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        let rgb = decoded.to_rgb8();

        assert_eq!(*rgb.get_pixel(0, 0), image::Rgb([255, 0, 0]));
        assert_eq!(*rgb.get_pixel(1, 0), image::Rgb([0, 255, 0]));
        assert_eq!(*rgb.get_pixel(0, 1), image::Rgb([0, 0, 255]));
        assert_eq!(*rgb.get_pixel(1, 1), image::Rgb([255, 255, 255]));
    }

    #[test]
    fn test_encode_region_at_boundary_succeeds() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 10, 10);
        let png = encode_region_as_png(&image, 0, 8, 10, 2)
            .expect("region at framebuffer boundary should succeed");
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 10);
        assert_eq!(decoded.height(), 2);
    }

    #[test]
    fn test_encode_region_corner() {
        let image = DecodedImage::new(PixelFormat::RgbA32, 100, 100);
        let png = encode_region_as_png(&image, 90, 90, 10, 10)
            .expect("bottom-right corner region should succeed");
        let decoder = image::ImageReader::new(std::io::Cursor::new(&png))
            .with_guessed_format()
            .unwrap();
        let decoded = decoder.decode().unwrap();
        assert_eq!(decoded.width(), 10);
        assert_eq!(decoded.height(), 10);
    }

    // ==================== SessionConfig Tests ====================

    #[test]
    fn test_session_config_construction() {
        let config = SessionConfig {
            session_id: "test-session".to_string(),
            user_id: "user-1".to_string(),
            asset_id: "asset-1".to_string(),
            host: "192.168.1.100".to_string(),
            port: 3389,
            username: "admin".to_string(),
            password: Some(SecretString::from("password123")),
            domain: Some("CORP".to_string()),
            desktop_width: 1920,
            desktop_height: 1080,
            expected_cert_fingerprint: "SHA256:dGVzdA==".to_string(),
            preconnected_fd: None,
            auth_mode: RdpAuthMode::Ntlm,
            supervisor_relay: None,
        };

        assert_eq!(config.session_id, "test-session");
        assert_eq!(config.port, 3389);
        assert_eq!(config.desktop_width, 1920);
        assert_eq!(config.desktop_height, 1080);
        assert_eq!(config.domain.as_deref(), Some("CORP"));
        assert!(config.preconnected_fd.is_none());
    }

    #[test]
    fn test_session_config_no_password() {
        let config = SessionConfig {
            session_id: "s".to_string(),
            user_id: "u".to_string(),
            asset_id: "a".to_string(),
            host: "host".to_string(),
            port: 3389,
            username: "user".to_string(),
            password: None,
            domain: None,
            desktop_width: 1280,
            desktop_height: 720,
            expected_cert_fingerprint: "SHA256:dGVzdA==".to_string(),
            preconnected_fd: None,
            auth_mode: RdpAuthMode::Ntlm,
            supervisor_relay: None,
        };

        assert!(config.password.is_none());
        assert!(config.domain.is_none());
    }

    #[test]
    fn test_session_config_with_preconnected_fd() {
        use std::os::unix::io::AsRawFd;

        let (sock_a, _sock_b) = std::os::unix::net::UnixStream::pair().unwrap();
        let _raw = sock_a.as_raw_fd();
        let fd: OwnedFd = sock_a.into();

        let config = SessionConfig {
            session_id: "preconn".to_string(),
            user_id: "u".to_string(),
            asset_id: "a".to_string(),
            host: "rdp-server".to_string(),
            port: 3389,
            username: "admin".to_string(),
            password: None,
            domain: None,
            desktop_width: 1920,
            desktop_height: 1080,
            expected_cert_fingerprint: "SHA256:dGVzdA==".to_string(),
            preconnected_fd: Some(fd),
            auth_mode: RdpAuthMode::Ntlm,
            supervisor_relay: None,
        };

        assert!(config.preconnected_fd.is_some());
    }

    #[test]
    fn test_connect_uses_preconnected_fd_when_available() {
        let source = include_str!("session.rs");
        assert!(
            source.contains("if let Some(fd) = config.preconnected_fd"),
            "connect() must check for preconnected_fd"
        );
        assert!(
            source.contains("from_raw_fd(fd.into_raw_fd())"),
            "connect() must convert OwnedFd to std TcpStream via from_raw_fd"
        );
        assert!(
            source.contains("Using pre-established connection from supervisor"),
            "connect() must log when using pre-established connection"
        );
    }

    #[test]
    fn test_connect_falls_back_to_direct_connect() {
        let source = include_str!("session.rs");
        let preconn_check = source
            .find("if let Some(fd) = config.preconnected_fd")
            .expect("preconnected_fd check must exist");
        let after_check = &source[preconn_check..];
        assert!(
            after_check.contains("tokio::net::lookup_host"),
            "Fallback path must perform DNS resolution"
        );
        assert!(
            after_check.contains("TcpStream::connect(server_addr)"),
            "Fallback path must use TcpStream::connect"
        );
    }

    #[test]
    fn test_session_command_variants() {
        let _input = SessionCommand::Input(RdpInputEvent::MouseMove { x: 10, y: 20 });
        let _resize = SessionCommand::Resize {
            width: 1920,
            height: 1080,
        };
        let _close = SessionCommand::Close;
    }

    // ==================== align_even Tests ====================

    #[test]
    fn test_align_even_already_even() {
        assert_eq!(align_even(0), 0);
        assert_eq!(align_even(2), 2);
        assert_eq!(align_even(720), 720);
        assert_eq!(align_even(1080), 1080);
        assert_eq!(align_even(1280), 1280);
        assert_eq!(align_even(1728), 1728);
        assert_eq!(align_even(1920), 1920);
    }

    #[test]
    fn test_align_even_odd_rounds_up() {
        assert_eq!(align_even(1), 2);
        assert_eq!(align_even(3), 4);
        assert_eq!(align_even(719), 720);
        assert_eq!(align_even(1079), 1080);
        assert_eq!(align_even(1117), 1118);
    }

    #[test]
    fn test_align_even_preserves_h264_requirement() {
        for v in 1..=2000u16 {
            let aligned = align_even(v);
            assert_eq!(aligned % 2, 0, "align_even({v}) = {aligned} is not even");
            assert!(
                aligned >= v,
                "align_even({v}) = {aligned} is smaller than input"
            );
            assert!(
                aligned - v <= 1,
                "align_even({v}) = {aligned} overshot by more than 1"
            );
        }
    }

    #[test]
    fn test_resize_dimensions_round_down_to_even() {
        let odd_widths: [(u16, u16); 4] = [(1921, 1920), (1367, 1366), (2561, 2560), (3841, 3840)];
        for (odd, expected) in odd_widths {
            let result = odd & !1;
            assert_eq!(
                result, expected,
                "Width {odd} & !1 should be {expected}, got {result}"
            );
        }
        let odd_heights: [(u16, u16); 4] = [(1079, 1078), (1201, 1200), (901, 900), (1441, 1440)];
        for (odd, expected) in odd_heights {
            let result = odd & !1;
            assert_eq!(
                result, expected,
                "Height {odd} & !1 should be {expected}, got {result}"
            );
        }
        let even_values: [u16; 5] = [1920, 1080, 1280, 720, 2560];
        for v in even_values {
            assert_eq!(v & !1, v, "Even value {v} should be unchanged by & !1");
        }
    }

    // ==================== H.264 encoder thread odd-dimension handling ====================

    #[test]
    fn test_encoder_thread_handles_odd_dimensions() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx =
            tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 0, cmd_rx.1, result_tx.0, "test-odd".to_string());

        let odd_w: u16 = 1727;
        let odd_h: u16 = 1117;
        let buf = vec![0u8; usize::from(odd_w) * usize::from(odd_h) * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf, odd_w, odd_h))
            .unwrap();

        let (frame, _elapsed) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame.width, align_even(odd_w));
        assert_eq!(frame.height, align_even(odd_h));
        assert!(
            !frame.data.is_empty(),
            "H.264 frame data should not be empty"
        );
        assert!(frame.is_keyframe, "First frame should be a keyframe");
    }

    #[test]
    fn test_encoder_thread_reconfigure_odd_dimensions() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx =
            tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(
            1280,
            720,
            0,
            cmd_rx.1,
            result_tx.0,
            "test-reconf-odd".to_string(),
        );

        cmd_rx
            .0
            .blocking_send(EncoderCommand::Reconfigure(1727, 1117))
            .unwrap();
        cmd_rx
            .0
            .blocking_send(EncoderCommand::ForceKeyframe)
            .unwrap();

        let buf = vec![0u8; usize::from(1728u16) * usize::from(1118u16) * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf, 1728, 1118))
            .unwrap();

        let (frame, _elapsed) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame.width, 1728);
        assert_eq!(frame.height, 1118);
        assert!(frame.is_keyframe);
    }

    #[test]
    fn test_encoder_thread_exact_fullscreen_scenario() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx =
            tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(
            1280,
            720,
            0,
            cmd_rx.1,
            result_tx.0,
            "test-fullscreen".to_string(),
        );

        let buf_720p = vec![128u8; 1280 * 720 * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf_720p, 1280, 720))
            .unwrap();
        let (frame1, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame1.width, 1280);
        assert_eq!(frame1.height, 720);

        let buf_odd = vec![64u8; 1728 * 1117 * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf_odd, 1728, 1117))
            .unwrap();
        let (frame2, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame2.width, 1728);
        assert_eq!(frame2.height, 1118);
        assert!(!frame2.data.is_empty());

        let buf_back = vec![200u8; 1280 * 720 * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf_back, 1280, 720))
            .unwrap();
        let (frame3, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame3.width, 1280);
        assert_eq!(frame3.height, 720);
    }

    #[test]
    fn test_encoder_thread_custom_bitrate() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx =
            tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(
            1280,
            720,
            20_000_000,
            cmd_rx.1,
            result_tx.0,
            "test-bitrate".to_string(),
        );

        let buf = vec![0u8; 1280 * 720 * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf, 1280, 720))
            .unwrap();
        let (frame, _) = result_tx.1.blocking_recv().unwrap();
        assert!(frame.is_keyframe);
        assert!(!frame.data.is_empty());
    }

    #[test]
    fn test_encoder_thread_zero_bitrate_uses_default() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx =
            tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(
            1280,
            720,
            0,
            cmd_rx.1,
            result_tx.0,
            "test-default-bitrate".to_string(),
        );

        let buf = vec![0u8; 1280 * 720 * 4];
        cmd_rx
            .0
            .blocking_send(EncoderCommand::Encode(buf, 1280, 720))
            .unwrap();
        let (frame, _) = result_tx.1.blocking_recv().unwrap();
        assert!(frame.is_keyframe);
        assert!(!frame.data.is_empty());
    }

    #[test]
    fn test_session_command_set_video_mode_has_bitrate() {
        let _cmd = SessionCommand::SetVideoMode {
            enabled: true,
            bitrate_bps: 10_000_000,
        };
        let _cmd_default = SessionCommand::SetVideoMode {
            enabled: false,
            bitrate_bps: 0,
        };
    }

    // ==================== Structural Regression Tests ====================

    /// Extract the body of the reactivation handler (the arm of the active
    /// session loop that applies a completed Deactivation-Reactivation
    /// Sequence), anchored on the `drive_reactivation` call.
    fn deactivate_all_handler_body() -> &'static str {
        let source = include_str!("session.rs");
        let start = source
            .find("let outcome = drive_reactivation(&activation_factory, &mut framed)")
            .expect("DeactivateAll handler must drive the reactivation sequence");
        let body = &source[start..];
        let end = body.find("_ => {}").unwrap_or(body.len());
        &body[..end]
    }

    /// Extract the body of `drive_reactivation` (the function that steps a
    /// fresh activation sequence until `Finalized`).
    fn drive_reactivation_body() -> &'static str {
        let source = include_str!("session.rs");
        let start = source
            .find("async fn drive_reactivation")
            .expect("drive_reactivation must exist");
        let body = &source[start..];
        let end = body.find("\n}\n").map(|pos| pos + 2).unwrap_or(body.len());
        &body[..end]
    }

    #[test]
    fn test_active_session_loop_handles_deactivate_all() {
        let drive_body = drive_reactivation_body();
        assert!(
            drive_body.contains("activation_factory.create()"),
            "drive_reactivation must create a fresh activation sequence from the factory"
        );
        assert!(
            drive_body.contains("single_sequence_step"),
            "drive_reactivation must use single_sequence_step for reactivation"
        );
        assert!(
            drive_body.contains("ConnectionActivationState::Finalized"),
            "drive_reactivation must check for Finalized state"
        );

        let handler_body = deactivate_all_handler_body();
        assert!(
            handler_body.contains("set_fastpath_processor"),
            "DeactivateAll handler must update fastpath processor"
        );
        assert!(
            handler_body.contains("set_share_id"),
            "DeactivateAll handler must propagate the renegotiated share_id \
             (IronRDP 0.17: the fastpath processor alone is not enough)"
        );
    }

    #[test]
    fn test_resize_handler_does_not_recreate_framebuffer() {
        let source = include_str!("session.rs");
        let resize_handler_start = source
            .find("Some(SessionCommand::Resize { width, height })")
            .expect("Resize handler must exist");
        let handler_body = &source[resize_handler_start..];
        let handler_end = handler_body
            .find("Some(SessionCommand::SetVideoMode")
            .or_else(|| handler_body.find("Some(SessionCommand::Close)"))
            .unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];

        assert!(
            !handler_body.contains("DecodedImage::new"),
            "Resize handler must NOT recreate DecodedImage (race condition: server still \
             sends updates at old resolution until DeactivateAll completes)"
        );
        assert!(
            !handler_body.contains("EncoderCommand::Reconfigure"),
            "Resize handler must NOT reconfigure encoder (done in DeactivateAll handler)"
        );
    }

    #[test]
    fn test_resize_handler_forces_both_dimensions_even() {
        let source = include_str!("session.rs");
        let resize_handler_start = source
            .find("Some(SessionCommand::Resize { width, height })")
            .expect("Resize handler must exist");
        let handler_body = &source[resize_handler_start..];
        let handler_end = handler_body
            .find("Some(SessionCommand::SetVideoMode")
            .or_else(|| handler_body.find("Some(SessionCommand::Close)"))
            .unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];

        let w_line = handler_body
            .lines()
            .find(|l| l.contains("let w ="))
            .expect("Resize handler must assign w");
        assert!(
            w_line.contains("& !1"),
            "Resize width must be forced even (& !1), found: {w_line}"
        );

        let h_line = handler_body
            .lines()
            .find(|l| l.contains("let h ="))
            .expect("Resize handler must assign h");
        assert!(
            h_line.contains("& !1"),
            "Resize height must be forced even (& !1) for H.264 YUV 4:2:0 compatibility, found: {h_line}"
        );
    }

    #[test]
    fn test_deactivate_all_sends_aligned_dimensions_to_web() {
        let handler_body = deactivate_all_handler_body();

        assert!(
            handler_body.contains("align_even(desktop_size.width)"),
            "DeactivateAll must align width before sending to web (prevents mismatch with encoder)"
        );
        assert!(
            handler_body.contains("align_even(desktop_size.height)"),
            "DeactivateAll must align height before sending to web (prevents mismatch with encoder)"
        );
        assert!(
            handler_body.contains("RdpDesktopResize"),
            "DeactivateAll must send RdpDesktopResize notification"
        );
    }

    #[test]
    fn test_deactivate_all_reconfigures_encoder() {
        let handler_body = deactivate_all_handler_body();

        assert!(
            handler_body.contains("DecodedImage::new"),
            "DeactivateAll handler must recreate DecodedImage with new resolution"
        );
        assert!(
            handler_body.contains("EncoderCommand::Reconfigure"),
            "DeactivateAll handler must reconfigure H.264 encoder for new resolution"
        );
        assert!(
            handler_body.contains("suppress_encoding_until"),
            "DeactivateAll handler must set encoding grace period to avoid black frames"
        );
        assert!(
            !handler_body.contains("framebuffer_dirty.store(true"),
            "DeactivateAll handler must NOT immediately set framebuffer_dirty (causes black frames)"
        );
    }

    #[test]
    fn test_encode_tick_respects_grace_period() {
        let source = include_str!("session.rs");
        let tick_start = source
            .find("H.264 encoding tick")
            .expect("encode tick comment must exist");
        let tick_body = &source[tick_start..];
        let tick_end = tick_body
            .find("Receive encoded H.264")
            .unwrap_or(tick_body.len());
        let tick_body = &tick_body[..tick_end];

        assert!(
            tick_body.contains("suppress_encoding_until"),
            "Encode tick must check suppress_encoding_until grace period"
        );
        assert!(
            tick_body.contains("EncoderCommand::ForceKeyframe"),
            "Encode tick must send ForceKeyframe when grace period expires"
        );
    }

    #[test]
    fn test_align_even_used_in_encoder_thread() {
        let source = include_str!("session.rs");
        let thread_start = source
            .find("fn spawn_encoder_thread")
            .expect("spawn_encoder_thread must exist");
        let fn_body = &source[thread_start..];
        let fn_end = fn_body
            .find("\n/// ")
            .or_else(|| fn_body.find("\nfn "))
            .unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("align_even"),
            "spawn_encoder_thread must use align_even to ensure H.264 YUV 4:2:0 compatibility"
        );
        assert!(
            fn_body.contains(".resize(expected,"),
            "spawn_encoder_thread must pad RGBA buffer when dimensions are aligned up"
        );
    }

    #[test]
    fn test_encode_uses_rgb_not_rgba() {
        let source = include_str!("session.rs");
        let encode_fn_start = source
            .find("fn encode_region_as_png")
            .expect("function must exist");
        let fn_body = &source[encode_fn_start..];
        let fn_end = fn_body.find("\nfn ").unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];

        assert!(
            fn_body.contains("Rgb8"),
            "encode_region_as_png must use Rgb8 to avoid transparent pixels"
        );
        let rgba8_str = ["Rgba", "8"].concat();
        assert!(
            !fn_body.contains(&rgba8_str),
            "encode_region_as_png must NOT use Rgba8 (alpha is undefined in RDP)"
        );
    }

    #[test]
    fn test_alpha_channel_stripped_in_encoding() {
        let source = include_str!("session.rs");
        let encode_fn = source
            .find("fn encode_region_as_png")
            .expect("encode_region_as_png function must exist");
        let fn_body = &source[encode_fn..];
        let fn_end = fn_body.find("\nfn ").unwrap_or(fn_body.len());
        let fn_body = &fn_body[..fn_end];
        assert!(
            fn_body.contains("pixel[0]")
                && fn_body.contains("pixel[1]")
                && fn_body.contains("pixel[2]"),
            "encode_region_as_png must extract R, G, B channels individually"
        );
        assert!(
            !fn_body.contains("pixel[3]"),
            "encode_region_as_png must NOT include alpha channel (pixel[3])"
        );
    }

    // ==================== VAU-001 RDP cert pinning Tests ====================
    //
    // Battle-tested coverage for the SPKI pinning layer that replaced the
    // pre-fix `NoCertificateVerification` (accept-any) verifier. These run
    // against an in-process rustls server presenting a self-signed leaf
    // generated by `rcgen`, isolating the pinning decision from the RDP
    // X.224 dance. Mirror of `host_key_behavioural_tests` in
    // vauban-proxy-ssh.
    mod vau001_cert_pinning {
        // Tests legitimately unwrap/expect/panic on setup failures; the
        // crate denies these in production code only.
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use super::super::{
            PinningServerCertVerifier, build_tls_config, constant_time_eq, spki_der,
            spki_sha256_fingerprint,
        };
        use rcgen::generate_simple_self_signed;
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::rustls;
        use tokio_rustls::rustls::client::danger::ServerCertVerifier as _;
        use tokio_rustls::rustls::pki_types::{self, CertificateDer, PrivateKeyDer, ServerName};
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        /// Generate a fresh self-signed leaf cert + PKCS#8 key (DER).
        fn gen_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let certified = generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen self-signed generation");
            let cert_der = certified.cert.der().clone();
            let key_der = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
            (cert_der, key_der)
        }

        fn make_server_config(
            cert: CertificateDer<'static>,
            key: PrivateKeyDer<'static>,
        ) -> Arc<rustls::ServerConfig> {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("server protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server single cert");
            Arc::new(cfg)
        }

        /// Drive a real TLS handshake from the PINNING client (built via
        /// the production `build_tls_config`) against an in-process rustls
        /// server presenting `cert`. Returns Ok iff the handshake -- SPKI
        /// pin AND signature verification -- succeeds.
        async fn run_handshake(
            cert: CertificateDer<'static>,
            key: PrivateKeyDer<'static>,
            expected_fingerprint: &str,
        ) -> Result<(), String> {
            let server_cfg = make_server_config(cert, key);
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let addr = listener.local_addr().map_err(|e| e.to_string())?;

            let acceptor = TlsAcceptor::from(server_cfg);
            // The server just completes the handshake and closes. We do NOT
            // exchange application data: a successful `connect().await` on the
            // client already proves the SPKI pin + signature passed, which is
            // the whole point. (Exchanging a byte would deadlock under the
            // current-thread test runtime if both sides blocked on read.)
            let server = tokio::spawn(async move {
                if let Ok((tcp, _)) = listener.accept().await
                    && let Ok(mut tls) = acceptor.accept(tcp).await
                {
                    let _ = tls.shutdown().await;
                }
            });

            let client_cfg = build_tls_config(expected_fingerprint).map_err(|e| e.to_string())?;
            let connector = TlsConnector::from(client_cfg);
            let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
            let server_name = ServerName::try_from("localhost").map_err(|e| e.to_string())?;
            let result = connector.connect(server_name, tcp).await;
            match result {
                Ok(mut tls) => {
                    let _ = tls.shutdown().await;
                    let _ = server.await;
                    Ok(())
                }
                Err(e) => {
                    server.abort();
                    Err(e.to_string())
                }
            }
        }

        #[test]
        fn spki_fingerprint_is_deterministic_and_formatted() {
            let (cert, _key) = gen_self_signed();
            let a = spki_sha256_fingerprint(&cert).expect("fingerprint");
            let b = spki_sha256_fingerprint(&cert).expect("fingerprint");
            assert_eq!(a, b, "fingerprint must be deterministic for one cert");
            assert!(
                a.starts_with("SHA256:"),
                "fingerprint must be prefixed with SHA256:, got {a}"
            );
            let b64 = a.trim_start_matches("SHA256:");
            assert_eq!(
                b64.len(),
                44,
                "SHA-256 digest base64 must be 44 chars (32 bytes + padding), got {}",
                b64.len()
            );
        }

        #[test]
        fn distinct_certs_have_distinct_fingerprints() {
            let (c1, _) = gen_self_signed();
            let (c2, _) = gen_self_signed();
            assert_ne!(
                spki_sha256_fingerprint(&c1).expect("fp1"),
                spki_sha256_fingerprint(&c2).expect("fp2"),
                "two independently-generated keys must hash differently"
            );
        }

        #[test]
        fn spki_der_is_subset_of_full_cert() {
            let (cert, _) = gen_self_signed();
            let spki = spki_der(&cert).expect("spki der");
            assert!(!spki.is_empty(), "SPKI DER must be non-empty");
            assert!(
                spki.len() < cert.as_ref().len(),
                "SPKI ({} bytes) must be a strict subset of the full cert \
                 DER ({} bytes)",
                spki.len(),
                cert.as_ref().len()
            );
        }

        #[test]
        fn constant_time_eq_matches_byte_semantics() {
            assert!(constant_time_eq(b"abc", b"abc"));
            assert!(constant_time_eq(b"", b""));
            assert!(!constant_time_eq(b"abc", b"abd"));
            assert!(!constant_time_eq(b"abc", b"ab"), "length mismatch -> false");
            assert!(!constant_time_eq(b"ab", b"abc"));
        }

        #[test]
        fn verifier_accepts_exact_spki_match() {
            let (cert, _) = gen_self_signed();
            let fp = spki_sha256_fingerprint(&cert).expect("fp");
            let verifier = PinningServerCertVerifier {
                expected_fingerprint: fp,
                provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            };
            let now = pki_types::UnixTime::now();
            let name = ServerName::try_from("localhost").expect("server name");
            assert!(
                verifier
                    .verify_server_cert(&cert, &[], &name, &[], now)
                    .is_ok(),
                "verifier must accept a cert whose SPKI matches the pin"
            );
        }

        #[test]
        fn verifier_rejects_mismatch_with_mitm_wording() {
            let (cert, _) = gen_self_signed();
            let verifier = PinningServerCertVerifier {
                expected_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    .to_string(),
                provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            };
            let now = pki_types::UnixTime::now();
            let name = ServerName::try_from("localhost").expect("server name");
            let err = verifier
                .verify_server_cert(&cert, &[], &name, &[], now)
                .expect_err("verifier MUST reject a mismatched pin");
            let msg = err.to_string();
            assert!(
                msg.contains("MITM") || msg.to_lowercase().contains("mismatch"),
                "the mismatch error must carry MITM/mismatch wording so the \
                 web connect handler can flip rdp_server_cert_mismatch. Got: {msg}"
            );
        }

        #[tokio::test]
        async fn pinning_handshake_succeeds_when_spki_matches() {
            let (cert, key) = gen_self_signed();
            let fp = spki_sha256_fingerprint(&cert).expect("fp");
            let res = run_handshake(cert, key, &fp).await;
            assert!(
                res.is_ok(),
                "TLS handshake must SUCCEED when the pinned SPKI matches the \
                 server cert: {res:?}"
            );
        }

        #[tokio::test]
        async fn pinning_handshake_fails_when_spki_differs() {
            let (cert, key) = gen_self_signed();
            let (other_cert, _other_key) = gen_self_signed();
            let real_fp = spki_sha256_fingerprint(&cert).expect("real fp");
            let wrong_fp = spki_sha256_fingerprint(&other_cert).expect("wrong fp");
            assert_ne!(real_fp, wrong_fp, "test setup: pins must differ");

            let res = run_handshake(cert, key, &wrong_fp).await;
            assert!(
                res.is_err(),
                "TLS handshake MUST FAIL (never silently accept a MITM) when \
                 the pinned SPKI differs from the server cert. This is the \
                 load-bearing VAU-001 regression: pre-fix the accept-any \
                 verifier returned Ok here."
            );
        }
    }

    /// Invariant-based tests for the Kerberos / Restricted Admin auth mode
    /// (phase A). These pin the fail-closed behaviors on the wire path.
    mod kerberos_auth_mode {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

        use super::*;
        use ironrdp::connector::sspi::NetworkProtocol;
        use ironrdp::connector::sspi::generator::NetworkRequest;
        use proptest::prelude::*;

        /// The relay refuses any non-TCP transport, for any payload. A
        /// dummy relay channel is fine: non-TCP returns before it is used.
        fn assert_relay_refuses(protocol: NetworkProtocol, data: Vec<u8>) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime");
            rt.block_on(async {
                let (tx, _rx) = mpsc::unbounded_channel::<Message>();
                let relay = Arc::new(SupervisorRelay::new(tx));
                let mut client = KerberosRelayNetworkClient {
                    relay,
                    session_id: "sess".to_string(),
                };
                let request = NetworkRequest {
                    protocol,
                    url: url::Url::parse(KERBEROS_KDC_SENTINEL_URL).expect("url"),
                    data,
                };
                let result = client.send(&request).await;
                prop_assert!(
                    result.is_err(),
                    "relay must refuse {:?} (fail-closed)",
                    protocol
                );
                Ok(())
            })
            .expect("prop body");
        }

        proptest! {
            /// `RdpAuthMode` round-trips through its canonical wire form for
            /// both variants; unknown strings never parse to a variant.
            #[test]
            fn auth_mode_parse_round_trips(garbage in "[a-z_]{0,32}") {
                for mode in [RdpAuthMode::Ntlm, RdpAuthMode::KerberosRestrictedAdmin] {
                    prop_assert_eq!(RdpAuthMode::parse(mode.as_str()), Some(mode));
                }
                // A random lowercase string only parses if it IS a canonical
                // form; otherwise it must be None (never a silent default).
                let parsed = RdpAuthMode::parse(&garbage);
                if garbage != "ntlm" && garbage != "kerberos_restricted_admin" {
                    prop_assert_eq!(parsed, None);
                }
            }

            /// The relay refuses UDP, HTTP and HTTPS for ANY payload.
            #[test]
            fn relay_refuses_non_tcp_for_any_payload(
                data in proptest::collection::vec(any::<u8>(), 0..64),
            ) {
                assert_relay_refuses(NetworkProtocol::Udp, data.clone());
                assert_relay_refuses(NetworkProtocol::Http, data.clone());
                assert_relay_refuses(NetworkProtocol::Https, data);
            }
        }

        /// Kerberos mode WITHOUT a supervisor relay fails closed (no NTLM
        /// fallback), while NTLM mode always builds its network-less client.
        #[test]
        fn session_network_client_fails_closed_without_relay() {
            let ntlm = SessionNetworkClient::for_auth_mode(RdpAuthMode::Ntlm, None, "s");
            assert!(matches!(ntlm, Ok(SessionNetworkClient::NtlmOnly(_))));

            let kerb_no_relay = SessionNetworkClient::for_auth_mode(
                RdpAuthMode::KerberosRestrictedAdmin,
                None,
                "s",
            );
            assert!(
                kerb_no_relay.is_err(),
                "Kerberos mode must fail closed without a supervisor KDC FD broker"
            );

            let (tx, _rx) = mpsc::unbounded_channel::<Message>();
            let relay = Arc::new(SupervisorRelay::new(tx));
            let kerb = SessionNetworkClient::for_auth_mode(
                RdpAuthMode::KerberosRestrictedAdmin,
                Some(relay),
                "s",
            );
            assert!(matches!(kerb, Ok(SessionNetworkClient::KerberosRelay(_))));
        }

        /// Framed Kerberos TCP I/O on a leased FD (UnixStream stand-in).
        #[test]
        fn kdc_framed_round_trip_over_socketpair() {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;

            let (client, mut server) = UnixStream::pair().expect("socketpair");
            let body = b"AS-REQ-bytes";
            let request = encode_kdc_request_frame(body);

            let reply_body = b"AS-REP-bytes";
            let mut expected = Vec::new();
            expected.extend_from_slice(&(reply_body.len() as u32).to_be_bytes());
            expected.extend_from_slice(reply_body);
            let expected_clone = expected.clone();

            let server_thread = std::thread::spawn(move || {
                let mut len_buf = [0u8; 4];
                server.read_exact(&mut len_buf).expect("len");
                let n = u32::from_be_bytes(len_buf) as usize;
                let mut req = vec![0u8; n];
                server.read_exact(&mut req).expect("body");
                assert_eq!(req, body);
                server.write_all(&expected_clone).expect("reply");
            });

            let owned = unsafe { OwnedFd::from_raw_fd(client.into_raw_fd()) };
            let got = kdc_framed_round_trip(owned, &request).expect("round-trip");
            assert_eq!(got, expected);
            server_thread.join().expect("join");
        }

        #[test]
        fn kdc_framed_round_trip_rejects_oversized_reply() {
            use std::io::{Read, Write};
            use std::os::unix::net::UnixStream;

            let (client, mut server) = UnixStream::pair().expect("socketpair");
            let over = (MAX_KDC_REPLY as u32) + 1;
            let server_thread = std::thread::spawn(move || {
                let mut sink = [0u8; 8];
                let _ = server.read(&mut sink);
                server.write_all(&over.to_be_bytes()).expect("len");
            });

            let owned = unsafe { OwnedFd::from_raw_fd(client.into_raw_fd()) };
            let err = kdc_framed_round_trip(owned, &[0, 0, 0, 1, 0x41]).expect_err("oversized");
            assert!(err.contains("too large"), "got {err}");
            let _ = server_thread.join();
        }

        /// Pure KDC framing helpers (no I/O).
        mod kdc_framing_proptests {
            use proptest::prelude::*;

            use super::{MAX_KDC_REPLY, decode_kdc_reply_len, encode_kdc_request_frame};

            proptest! {
                #![proptest_config(ProptestConfig::with_cases(128))]

                /// encode → length prefix matches body length.
                #[test]
                fn encode_prefix_roundtrips_body(
                    body in prop::collection::vec(any::<u8>(), 0..1024)
                ) {
                    let frame = encode_kdc_request_frame(&body);
                    prop_assert_eq!(frame.len(), 4 + body.len());
                    let len = u32::from_be_bytes([
                        frame[0], frame[1], frame[2], frame[3],
                    ]) as usize;
                    prop_assert_eq!(len, body.len());
                    prop_assert_eq!(&frame[4..], body.as_slice());
                    let decoded = decode_kdc_reply_len([
                        frame[0], frame[1], frame[2], frame[3],
                    ])
                    .expect("body under MAX_KDC_REPLY");
                    prop_assert_eq!(decoded, body.len());
                }

                /// Lengths above MAX_KDC_REPLY are rejected.
                #[test]
                fn oversized_u32_rejected(
                    overshoot in 1u32..=1024u32,
                ) {
                    let len = (MAX_KDC_REPLY as u32).saturating_add(overshoot);
                    // saturating_add can clamp at u32::MAX; still >= fence+1
                    // when overshoot >= 1 and MAX fits in u32.
                    prop_assume!(len as usize > MAX_KDC_REPLY);
                    let err = decode_kdc_reply_len(len.to_be_bytes()).unwrap_err();
                    prop_assert!(
                        err.contains("too large"),
                        "unexpected err: {err}"
                    );
                }

                /// Lengths at or below the fence are accepted.
                #[test]
                fn fence_accepts_upto_max(
                    len in 0usize..=MAX_KDC_REPLY,
                ) {
                    let be = (len as u32).to_be_bytes();
                    prop_assert_eq!(decode_kdc_reply_len(be).unwrap(), len);
                }
            }
        }
    }
}
