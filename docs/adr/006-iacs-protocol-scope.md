# ADR 006: IACS protocol profile scope

**Status:** Accepted  
**Date:** 2026-08-17  
**Crate:** 0.9.37  
**Related:**
[IACS Proxy Architecture 1.1](../technical/Vauban_IACS_Proxy_Architecture_EN(1.1).md),
[IACS Inspect Capture 1.1](../technical/Vauban_IACS_Inspect_Capture_EN(1.1).md),
[ADR 001 -- Recording durability](001-recording-durability-per-protocol.md)

## Context

`vauban-proxy-iacs` already gates typed IACS assets on the **wire
family** of the first TCP frames (`shared::iacs_protocol`), then
switches to full passthrough. Inspect Capture dissects the recorded
PCAP into `Read` / `Cmd` / `Exception`. Four families shipped first
(Modbus/TCP, OPC-UA Binary, PROFINET DCE/RPC, IEC 60870-5-104).

Operators also need EtherNet/IP, BACnet, DNP3, and IEC 61850. Those
names each cover several transports. Treating "EtherNet/IP" or
"BACnet" as a single tunnel type would promise UDP, multicast, or
layer-2 traffic that the IACS sshd cannot carry: the proxy accepts
only `direct-tcpip` to a pinned `(host, port)`, and the supervisor
brokers only `TcpConnectRequest`. SSH has no native UDP channel.

The product needs an explicit in/out list so engineering (EWS over
TCP) is profiled and process-bus / discovery traffic is not silently
mis-sold as a bastion feature.

## Decision

1. **In scope -- TCP `direct-tcpip` only**, same MVP as Modbus/IEC-104
   (family peek + fail-closed mismatch, then passthrough; Inspect
   classifies after the fact). No live DPI of CIP services, DNP3
   function codes, or MMS Write.

   | `asset_type` | `industrial_protocol` | Default port | Peek |
   |--------------|-----------------------|--------------|------|
   | `iacs_enip` | `enip` | 44818 | CIP encapsulation header (24 bytes), command allowlist (`RegisterSession` 0x0065, `SendRRData` 0x006F, ...) |
   | `iacs_bacnet_sc` | `bacnet_sc` | 443 | TLS record `16 03` (or HTTP/WebSocket upgrade). Confirms **TLS**, not a BACnet APDU |
   | `iacs_dnp3` | `dnp3` | 20000 | IEEE 1815 link start `05 64` + length |
   | `iacs_iec61850` | `iec61850` | 102 | TPKT `03 00` + COTP; **reject** S7comm magic `0x32` (same port 102) |

2. **Out of scope -- no new transport in this lot.**

   - **EtherNet/IP implicit UDP 2222.** Cyclic Class 0/1 I/O, often
     multicast, 1-10 ms. This is the machine bus, not the remote
     engineering path. SSH cannot encapsulate it; a UDP-over-TCP
     framer would be a new Capsicum + supervisor + datagram-PCAP
     product. Implicit stays on the OT LAN. Engineering already uses
     **explicit TCP 44818** (Studio 5000 / RSLinx).
   - **BACnet/IP unicast UDP 47808.** Daily BMS polling after the
     device address is known, but it is UDP. The IACS proxy has no
     UDP socket. Operators who need a bastion path use **BACnet/SC**
     (TLS) or keep `iacs_tcp` as an honest catch-all.
   - **BACnet broadcast (Who-Is / I-Am / BBMD).** Commissioning and
     inter-VLAN discovery. A unicast SSH tunnel swallows broadcasts.
     The standard way across a router is Foreign Device → BBMD, not
     the bastion.
   - **UDP-over-SSH encapsulation.** Not `ssh -L`. Would require an
     EWS sidecar, a bastion deframer, `sendto`, sandbox allowances,
     and datagram-aware recording. Separate ADR if ever needed.
   - **IEC 61850 GOOSE / SV.** Ethernet L2 multicast. Incompatible
     with `direct-tcpip`. This profile is **MMS/TCP only**.
   - **Live command filtering** (block CIP Set, DNP3 Operate, MMS
     Write on the wire). Unchanged: after family confirmation the
     relay is passthrough. Inspect remains the `Cmd` surface.

3. **`iacs_tcp` remains the catch-all** for S7, MQTT/TLS, BACnet/IP,
   and anything not in the table. A mislabeled row must not brick
   connectivity (`from_industrial_label` unknown → passthrough).

4. **Detect-only wire families.** `classify_peek` may return
   `BacnetIp` (BVLL `0x81`) or `S7` (TPKT + S7comm `0x32`) so a typed
   profile fails **Foreign** immediately instead of waiting for the
   5 s / 4 KiB unconfirmed deadline. There is no `ExpectedProfile`
   for those labels.

5. **Peek order** (first match wins): Modbus → OPC-UA → IEC-104 →
   DNP3 (`05 64`) → ENIP → IEC 61850 → BACnet/SC → BACnet/IP →
   PROFINET (`05 00`) → S7 → Unknown. DNP3 is classified before
   PROFINET so `05 64` cannot be confused with DCE/RPC `05 00`.

## Consequences

- Asset create / edit grows four IACS variants; SQL CHECK
  `assets_asset_type_chk` is widened in a **new** migration (the
  2026-05-08 IACS tunnel migration is not rewritten).
- Access rules saved with the "IACS (all industrial protocols)"
  master checkbox before this ADR still persist the five-token
  snapshot. Migration `20260817160000_iacs_access_rule_profiles`
  appends the four new tokens; `expand_legacy_all_iacs_protocols`
  does the same at read time so `/assets` and `iacs_tunnel` connect
  do not wait on a re-save. A Modbus-only (partial) rule stays
  partial.
- BACnet/SC Inspect never emits `Cmd` on ciphertext (same honesty as
  OPC-UA Sign&Encrypt). Operators still use Wireshark for decrypted
  APDUs.
- IEC 61850 MMS on port 102 can still look like TPKT until COTP/S7
  is visible; short prefixes stay `Unknown` (need more data).
- Roadmaps must not claim "Vauban tunnels EtherNet/IP I/O" or
  "BACnet discovery" without a new ADR that overturns this one.
- Threat inventory (R4) for these four integrations: the trust
  anchor is the session's `industrial_protocol` column / IPC label,
  not bytes from the stream. A rewritten first PDU that belongs to
  another family closes the channel.
