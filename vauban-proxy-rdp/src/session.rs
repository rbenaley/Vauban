//! RDP session management using IronRDP.
//!
//! Each session manages a full RDP connection lifecycle:
//! TCP connect -> TLS upgrade -> CredSSP/NLA -> active session.
//! Display updates are encoded as PNG regions and sent via IPC.

use crate::error::{SessionError, SessionResult};
use crate::video_encoder::VideoEncoder;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};
use ironrdp::connector::{self, connection_activation::ConnectionActivationState, ClientConnector, ConnectionResult, Credentials, DesktopSize};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::geometry::Rectangle as _;
use ironrdp::pdu::rdp::capability_sets::{self, MajorPlatformType};
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{fast_path, ActiveStage, ActiveStageOutput};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::input::{self as rdp_input, Database as InputDatabase};
use ironrdp::dvc::DrdynvcClient;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::core::WriteBuf;
use ironrdp_tokio::single_sequence_step;
use ironrdp_tokio::{FramedWrite as _, NetworkClient};
use secrecy::{ExposeSecret, SecretString};
use shared::messages::{Message, RdpInputEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

        // Resolve target address (with timeout)
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

        // TCP connect (with timeout)
        let stream = tokio::time::timeout(
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
        .map_err(|e| SessionError::ConnectionFailed(format!("TCP connect failed: {e}")))?;

        let client_addr = stream
            .local_addr()
            .map_err(|e| SessionError::ConnectionFailed(format!("local addr: {e}")))?;

        trace!(session_id = %config.session_id, "TCP connection established");

        let drdynvc = DrdynvcClient::new()
            .with_dynamic_channel(DisplayControlClient::new(|caps| {
                trace!("Display Control capabilities: {:?}", caps);
                Ok(Vec::new())
            }));
        let mut connector = ClientConnector::new(connector_config, client_addr)
            .with_static_channel(drdynvc);

        // Wrap in IronRDP framing
        let mut framed = ironrdp_tokio::TokioFramed::new(stream);

        // Drive connection up to TLS upgrade point
        let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
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

        let tls_config = build_tls_config();
        let tls_connector = tokio_rustls::TlsConnector::from(tls_config);

        let tcp_stream = framed.into_inner_no_leftover();
        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tls_connector.connect(server_name.clone(), tcp_stream),
        )
        .await
        .map_err(|_| SessionError::TlsUpgradeFailed("TLS handshake timed out after 10s".to_string()))?
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

        // Finalize connection (CredSSP + remaining handshake)
        let mut network_client = NtlmOnlyNetworkClient;
        let connection_result = ironrdp_tokio::connect_finalize(
            upgraded,
            connector,
            &mut tls_framed,
            &mut network_client,
            connector::ServerName::new(config.host.clone()),
            server_public_key,
            None,
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
                None, // audit_tx: future recording support
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
fn align_even(v: u16) -> u16 {
    (v + 1) & !1
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
                    if aw != encoder.dimensions().0 || ah != encoder.dimensions().1 {
                        if let Err(e) = encoder.reconfigure(aw, ah) {
                            warn!(session_id = %session_id, error = %e, "Encoder thread: reconfigure failed");
                            continue;
                        }
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

/// Main processing loop for an active RDP session.
async fn active_session_loop(
    session_id: String,
    connection_result: ConnectionResult,
    mut framed: ironrdp_tokio::TokioFramed<tokio_rustls::client::TlsStream<TcpStream>>,
    web_tx: mpsc::Sender<Message>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
    #[allow(unused_variables)] audit_tx: Option<mpsc::Sender<Message>>,
) -> SessionResult<()> {
    let desktop_w = connection_result.desktop_size.width;
    let desktop_h = connection_result.desktop_size.height;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, desktop_w, desktop_h);
    let mut active_stage = ActiveStage::new(connection_result);
    let mut input_db = InputDatabase::new();
    let mut graphics_update_count: u64 = 0;
    let mut _response_frame_count: u64 = 0;
    let mut pdu_count: u64 = 0;

    let mut video_mode = false;
    let framebuffer_dirty = Arc::new(AtomicBool::new(false));
    let mut encode_interval = interval(std::time::Duration::from_millis(16)); // 60 FPS max

    // Channel for receiving encoded H.264 frames from the encoder thread
    let (encoded_tx, mut encoded_rx) = mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(4);
    // Channel for sending framebuffer snapshots to the encoder thread
    let mut encoder_snapshot_tx: Option<mpsc::Sender<EncoderCommand>> = None;

    // Performance metrics: log every 5 seconds
    let mut perf_interval = interval(std::time::Duration::from_secs(5));
    let mut perf_gfx_updates: u64 = 0;
    let mut perf_encoded_frames: u64 = 0;
    let mut perf_dirty_skips: u64 = 0;
    let mut perf_encode_time_us: u64 = 0;

    trace!(session_id = %session_id, "Active session loop started");

    loop {
        tokio::select! {
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
                        ActiveStageOutput::DeactivateAll(_) => {
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
                        ActiveStageOutput::DeactivateAll(mut connection_activation) => {
                            debug!(session_id = %session_id, "Deactivation-Reactivation Sequence started");
                            let mut buf = WriteBuf::new();
                            loop {
                                single_sequence_step(&mut framed, &mut *connection_activation, &mut buf)
                                    .await
                                    .map_err(|e| SessionError::SessionFailed(
                                        format!("Deactivation-Reactivation failed: {e}")
                                    ))?;

                                if let ConnectionActivationState::Finalized {
                                    io_channel_id,
                                    user_channel_id,
                                    desktop_size,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                } = connection_activation.connection_activation_state()
                                {
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
                                            io_channel_id,
                                            user_channel_id,
                                            enable_server_pointer,
                                            pointer_software_rendering,
                                        }
                                        .build(),
                                    );
                                    active_stage.set_enable_server_pointer(enable_server_pointer);

                                    if let Some(ref tx) = encoder_snapshot_tx {
                                        let _ = tx.try_send(EncoderCommand::Reconfigure(
                                            desktop_size.width,
                                            desktop_size.height,
                                        ));
                                        let _ = tx.try_send(EncoderCommand::ForceKeyframe);
                                        framebuffer_dirty.store(true, Ordering::Relaxed);
                                    }

                                    let _ = web_tx.send(Message::RdpDesktopResize {
                                        session_id: session_id.clone(),
                                        width: desktop_size.width,
                                        height: desktop_size.height,
                                    }).await;
                                    info!(
                                        session_id = %session_id,
                                        width = desktop_size.width,
                                        height = desktop_size.height,
                                        "Desktop resized after reactivation"
                                    );
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Handle commands from web
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SessionCommand::Input(input_event)) => {
                        let operations = translate_input_event(input_event);
                        let fastpath_events = input_db.apply(operations);

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
                        let h = height.max(200);
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
                    let avg_encode_ms = if perf_encoded_frames > 0 {
                        perf_encode_time_us / perf_encoded_frames / 1000
                    } else {
                        0
                    };
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
        RdpInputEvent::WheelScroll {
            vertical,
            amount,
        } => {
            vec![rdp_input::Operation::WheelRotations(
                rdp_input::WheelRotations {
                    is_vertical: vertical,
                    rotation_units: amount,
                },
            )]
        }

        // High-level variants from web frontend
        RdpInputEvent::MouseButton { button, pressed, x, y } => {
            let Some(btn) = map_mouse_button(button) else {
                return vec![];
            };
            let mut ops = vec![rdp_input::Operation::MouseMove(rdp_input::MousePosition { x, y })];
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
                        rotation_units: -delta_y, // browser delta is inverted
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
        "Digit1" => 0x02, "Digit2" => 0x03, "Digit3" => 0x04,
        "Digit4" => 0x05, "Digit5" => 0x06, "Digit6" => 0x07,
        "Digit7" => 0x08, "Digit8" => 0x09, "Digit9" => 0x0A,
        "Digit0" => 0x0B, "Minus" => 0x0C, "Equal" => 0x0D,
        "Backspace" => 0x0E, "Tab" => 0x0F,
        "KeyQ" => 0x10, "KeyW" => 0x11, "KeyE" => 0x12, "KeyR" => 0x13,
        "KeyT" => 0x14, "KeyY" => 0x15, "KeyU" => 0x16, "KeyI" => 0x17,
        "KeyO" => 0x18, "KeyP" => 0x19,
        "BracketLeft" => 0x1A, "BracketRight" => 0x1B,
        "Enter" => 0x1C,
        "ControlLeft" => 0x1D,
        "KeyA" => 0x1E, "KeyS" => 0x1F, "KeyD" => 0x20, "KeyF" => 0x21,
        "KeyG" => 0x22, "KeyH" => 0x23, "KeyJ" => 0x24, "KeyK" => 0x25,
        "KeyL" => 0x26,
        "Semicolon" => 0x27, "Quote" => 0x28, "Backquote" => 0x29,
        "ShiftLeft" => 0x2A, "Backslash" => 0x2B,
        "KeyZ" => 0x2C, "KeyX" => 0x2D, "KeyC" => 0x2E, "KeyV" => 0x2F,
        "KeyB" => 0x30, "KeyN" => 0x31, "KeyM" => 0x32,
        "Comma" => 0x33, "Period" => 0x34, "Slash" => 0x35,
        "ShiftRight" => 0x36, "NumpadMultiply" => 0x37,
        "AltLeft" => 0x38, "Space" => 0x39, "CapsLock" => 0x3A,
        "F1" => 0x3B, "F2" => 0x3C, "F3" => 0x3D, "F4" => 0x3E,
        "F5" => 0x3F, "F6" => 0x40, "F7" => 0x41, "F8" => 0x42,
        "F9" => 0x43, "F10" => 0x44,
        "NumLock" => 0x45, "ScrollLock" => 0x46,
        "Numpad7" => 0x47, "Numpad8" => 0x48, "Numpad9" => 0x49,
        "NumpadSubtract" => 0x4A,
        "Numpad4" => 0x4B, "Numpad5" => 0x4C, "Numpad6" => 0x4D,
        "NumpadAdd" => 0x4E,
        "Numpad1" => 0x4F, "Numpad2" => 0x50, "Numpad3" => 0x51,
        "Numpad0" => 0x52, "NumpadDecimal" => 0x53,
        "F11" => 0x57, "F12" => 0x58,
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

fn build_tls_config() -> Arc<rustls::ClientConfig> {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    // CredSSP does not support TLS session resumption
    config.resumption = rustls::client::Resumption::disabled();

    Arc::new(config)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &pki_types::CertificateDer<'_>,
        _: &[pki_types::CertificateDer<'_>],
        _: &pki_types::ServerName<'_>,
        _: &[u8],
        _: pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
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

fn extract_tls_server_public_key(
    cert: &pki_types::CertificateDer<'_>,
) -> Result<Vec<u8>, String> {
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

    #[test]
    fn test_translate_key_pressed() {
        let ops = translate_input_event(RdpInputEvent::KeyPressed { scancode: 0x1E });
        assert_eq!(ops.len(), 1);
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
        let ops = translate_input_event(RdpInputEvent::Keyboard {
            code: "KeyA".to_string(),
            key: "a".to_string(),
            pressed: true,
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
        });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_release() {
        let ops = translate_input_event(RdpInputEvent::Keyboard {
            code: "KeyA".to_string(),
            key: "a".to_string(),
            pressed: false,
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
        });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_unknown_key() {
        let ops = translate_input_event(RdpInputEvent::Keyboard {
            code: "UnknownKey".to_string(),
            key: "?".to_string(),
            pressed: true,
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
        });
        assert!(ops.is_empty());
    }

    #[test]
    fn test_translate_extended_key() {
        let ops = translate_input_event(RdpInputEvent::KeyPressed { scancode: 0xE048 });
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn test_translate_high_level_keyboard_extended_key() {
        let ops = translate_input_event(RdpInputEvent::Keyboard {
            code: "ArrowUp".to_string(),
            key: "ArrowUp".to_string(),
            pressed: true,
            shift: false,
            ctrl: false,
            alt: false,
            meta: false,
        });
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
            255, 0,   0,   0,   // red, alpha=0
            0,   255, 0,   0,   // green, alpha=0
            0,   0,   255, 0,   // blue, alpha=0
            255, 255, 255, 0,   // white, alpha=0
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
        };

        assert_eq!(config.session_id, "test-session");
        assert_eq!(config.port, 3389);
        assert_eq!(config.desktop_width, 1920);
        assert_eq!(config.desktop_height, 1080);
        assert_eq!(config.domain.as_deref(), Some("CORP"));
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
        };

        assert!(config.password.is_none());
        assert!(config.domain.is_none());
    }

    #[test]
    fn test_session_command_variants() {
        let _input = SessionCommand::Input(RdpInputEvent::MouseMove { x: 10, y: 20 });
        let _resize = SessionCommand::Resize { width: 1920, height: 1080 };
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
            assert!(aligned >= v, "align_even({v}) = {aligned} is smaller than input");
            assert!(aligned - v <= 1, "align_even({v}) = {aligned} overshot by more than 1");
        }
    }

    // ==================== H.264 encoder thread odd-dimension handling ====================

    #[test]
    fn test_encoder_thread_handles_odd_dimensions() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx = tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 0, cmd_rx.1, result_tx.0, "test-odd".to_string());

        let odd_w: u16 = 1727;
        let odd_h: u16 = 1117;
        let buf = vec![0u8; usize::from(odd_w) * usize::from(odd_h) * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf, odd_w, odd_h)).unwrap();

        let (frame, _elapsed) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame.width, align_even(odd_w));
        assert_eq!(frame.height, align_even(odd_h));
        assert!(!frame.data.is_empty(), "H.264 frame data should not be empty");
        assert!(frame.is_keyframe, "First frame should be a keyframe");
    }

    #[test]
    fn test_encoder_thread_reconfigure_odd_dimensions() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx = tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 0, cmd_rx.1, result_tx.0, "test-reconf-odd".to_string());

        cmd_rx.0.blocking_send(EncoderCommand::Reconfigure(1727, 1117)).unwrap();
        cmd_rx.0.blocking_send(EncoderCommand::ForceKeyframe).unwrap();

        let buf = vec![0u8; usize::from(1728u16) * usize::from(1118u16) * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf, 1728, 1118)).unwrap();

        let (frame, _elapsed) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame.width, 1728);
        assert_eq!(frame.height, 1118);
        assert!(frame.is_keyframe);
    }

    #[test]
    fn test_encoder_thread_exact_fullscreen_scenario() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx = tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 0, cmd_rx.1, result_tx.0, "test-fullscreen".to_string());

        let buf_720p = vec![128u8; 1280 * 720 * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf_720p, 1280, 720)).unwrap();
        let (frame1, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame1.width, 1280);
        assert_eq!(frame1.height, 720);

        let buf_odd = vec![64u8; 1728 * 1117 * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf_odd, 1728, 1117)).unwrap();
        let (frame2, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame2.width, 1728);
        assert_eq!(frame2.height, 1118);
        assert!(!frame2.data.is_empty());

        let buf_back = vec![200u8; 1280 * 720 * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf_back, 1280, 720)).unwrap();
        let (frame3, _) = result_tx.1.blocking_recv().unwrap();
        assert_eq!(frame3.width, 1280);
        assert_eq!(frame3.height, 720);
    }

    #[test]
    fn test_encoder_thread_custom_bitrate() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx = tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 20_000_000, cmd_rx.1, result_tx.0, "test-bitrate".to_string());

        let buf = vec![0u8; 1280 * 720 * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf, 1280, 720)).unwrap();
        let (frame, _) = result_tx.1.blocking_recv().unwrap();
        assert!(frame.is_keyframe);
        assert!(!frame.data.is_empty());
    }

    #[test]
    fn test_encoder_thread_zero_bitrate_uses_default() {
        let cmd_rx = tokio::sync::mpsc::channel::<EncoderCommand>(8);
        let mut result_tx = tokio::sync::mpsc::channel::<(crate::video_encoder::VideoFrame, u64)>(8);

        spawn_encoder_thread(1280, 720, 0, cmd_rx.1, result_tx.0, "test-default-bitrate".to_string());

        let buf = vec![0u8; 1280 * 720 * 4];
        cmd_rx.0.blocking_send(EncoderCommand::Encode(buf, 1280, 720)).unwrap();
        let (frame, _) = result_tx.1.blocking_recv().unwrap();
        assert!(frame.is_keyframe);
        assert!(!frame.data.is_empty());
    }

    #[test]
    fn test_session_command_set_video_mode_has_bitrate() {
        let _cmd = SessionCommand::SetVideoMode { enabled: true, bitrate_bps: 10_000_000 };
        let _cmd_default = SessionCommand::SetVideoMode { enabled: false, bitrate_bps: 0 };
    }

    // ==================== Structural Regression Tests ====================

    #[test]
    fn test_active_session_loop_handles_deactivate_all() {
        let source = include_str!("session.rs");
        assert!(
            source.contains("DeactivateAll(mut connection_activation)"),
            "active_session_loop must handle ActiveStageOutput::DeactivateAll"
        );
        assert!(
            source.contains("single_sequence_step"),
            "DeactivateAll handler must use single_sequence_step for reactivation"
        );
        assert!(
            source.contains("ConnectionActivationState::Finalized"),
            "DeactivateAll handler must check for Finalized state"
        );
        assert!(
            source.contains("set_fastpath_processor"),
            "DeactivateAll handler must update fastpath processor"
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
    fn test_deactivate_all_reconfigures_encoder() {
        let source = include_str!("session.rs");
        let deactivate_start = source
            .find("DeactivateAll(mut connection_activation)")
            .expect("DeactivateAll handler must exist");
        let handler_body = &source[deactivate_start..];
        let handler_end = handler_body.find("_ => {}").unwrap_or(handler_body.len());
        let handler_body = &handler_body[..handler_end];

        assert!(
            handler_body.contains("DecodedImage::new"),
            "DeactivateAll handler must recreate DecodedImage with new resolution"
        );
        assert!(
            handler_body.contains("EncoderCommand::Reconfigure"),
            "DeactivateAll handler must reconfigure H.264 encoder for new resolution"
        );
        assert!(
            handler_body.contains("EncoderCommand::ForceKeyframe"),
            "DeactivateAll handler must force a keyframe after resize"
        );
    }

    #[test]
    fn test_align_even_used_in_encoder_thread() {
        let source = include_str!("session.rs");
        let thread_start = source
            .find("fn spawn_encoder_thread")
            .expect("spawn_encoder_thread must exist");
        let fn_body = &source[thread_start..];
        let fn_end = fn_body.find("\n/// ").or_else(|| fn_body.find("\nfn ")).unwrap_or(fn_body.len());
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
            fn_body.contains("pixel[0]") && fn_body.contains("pixel[1]") && fn_body.contains("pixel[2]"),
            "encode_region_as_png must extract R, G, B channels individually"
        );
        assert!(
            !fn_body.contains("pixel[3]"),
            "encode_region_as_png must NOT include alpha channel (pixel[3])"
        );
    }
}
