# Runbook -- IACS protocol profiles smoke test

> Manual check after shipping **ADR 006** typed profiles
> (`iacs_enip`, `iacs_bacnet_sc`, `iacs_dnp3`, `iacs_iec61850`).
> CI covers classify / gate / Inspect dissectors and asset vocabulary;
> staging proves a live EWS tunnel and Inspect labels on real PCAPs.
>
> Audience: release / staging operators.
> Severity: **BLOCKING** when `[industrial].enabled = true` and any of
> the four new asset types is offered to operators.

Related:

- [ADR 006](../adr/006-iacs-protocol-scope.md)
- [IACS Inspect Capture 1.1](../technical/Vauban_IACS_Inspect_Capture_EN(1.1).md) §5.2 / §9
- [IACS Proxy Architecture 1.1](../technical/Vauban_IACS_Proxy_Architecture_EN(1.1).md)
- Lint: `vauban-web/scripts/check_iacs_asset_type_exhaustive.sh`,
  `vauban-proxy-iacs/scripts/check_iacs_protocol_gate.sh`
- Lab probes (via `ssh -L`): `.cursor/audits/iacs_enip_tcp_probe.py`,
  `iacs_dnp3_tcp_probe.py`, `iacs_iec61850_tcp_probe.py`,
  `iacs_bacnet_sc_tcp_probe.py`

## Automated prerequisites

```bash
bash vauban-web/scripts/check_iacs_asset_type_exhaustive.sh
bash vauban-proxy-iacs/scripts/check_iacs_protocol_gate.sh
rtk cargo clippy -p shared -p vauban-web-evidence -p vauban-proxy-iacs -p vauban-web --all-targets -- -D warnings
rtk cargo test -p shared -p vauban-web-evidence -p vauban-proxy-iacs -p vauban-web -- iacs_protocol -- --test-threads=1
rtk cargo test -p vauban-web -- enip -- --test-threads=1
rtk cargo test -p vauban-web -- dnp3 -- --test-threads=1
rtk cargo test -p vauban-web -- bacnet -- --test-threads=1
rtk cargo test -p vauban-web -- iec61850 -- --test-threads=1
```

## Lab prerequisites

- `[industrial].enabled = true`.
- An EWS enrolled for IACS tunnels.
- Four assets (or one each, sequential): EtherNet/IP :44818, BACnet/SC
  :443, DNP3 :20000, IEC 61850 MMS :102.
- Ability to open Inspect Capture on the finalized recording.

## A -- Create + tunnel

1. Create each of the four asset types from `/assets/manage` (default
   ports must pre-fill except you may override).
2. Confirm a `role:user` whose access rule has
   **IACS (all industrial protocols)** sees each asset on `/assets`
   (including rules saved *before* ADR 006 -- do not require a
   re-save; migration `20260817160000_iacs_access_rule_profiles`
   plus read-time expansion cover the old five-token snapshot).
3. From the EWS, open an `ssh -L` tunnel as documented on the IACS
   status page and send a native client handshake (RegisterSession,
   TLS ClientHello, DNP3 link, TPKT/COTP).
4. Expect the proxy log `iacs_protocol_confirmed` and a live session.

Pass: asset persists with the typed `asset_type`; it is visible on
`/assets` under an all-IACS rule; tunnel stays up after the first
matching PDU.

## B -- Inspect Cmd (DNP3 Operate / EIP SetAttribute)

1. On the DNP3 asset, send an application **Operate** (or Direct
   Operate). Finalize the session; open Inspect.
2. On the EtherNet/IP asset, send **SetAttributeSingle** (or
   Forward_Open) inside `SendRRData`. Finalize; open Inspect.
3. Expect at least one row classified `Cmd` for each capture.

Pass: Inspect shows `Cmd` for Operate and SetAttribute; summaries
mention DNP3 / ENIP.

## C -- BACnet/SC handshake is Read only

1. Open a TLS (or WebSocket upgrade) session to the BACnet/SC asset.
2. Finalize; open Inspect.
3. Handshake / HTTP upgrade rows are `Read`. Encrypted application
   records must **not** appear as `Cmd`.

Pass: no `Cmd` on the BACnet/SC capture.

## Related links

- [IACS EWS onboarding](iacs_ews_onboarding.md)
- [IACS gzip off-thread smoke](iacs_gzip_offthread_smoke_test.md)
- [Adversarial review](adversarial_review.md)
