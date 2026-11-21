# Runbook -- Moving the IronRDP pin

> What to do, in order, each time the commit of IronRDP that the
> workspace builds from changes. The proxy carries code derived from
> modules IronRDP keeps private; nothing in the build says when those
> modules change upstream. This checklist is that signal.
>
> Audience: the developer or agent who moves the pin.
> Severity: **BLOCKING**. A pin moved without sections 2 to 6 is not
> ready to merge.

Related:

- [RDP Kerberos modes](../technical/Vauban_RDP_Kerberos_Modes_EN(1.0).md)
- [RDP Architecture](../technical/Vauban_RDP_Architecture_EN(1.0).md)
- [IronRDP upgrade smoke test](ironrdp_migration_smoke_test.md)
- [Remote Credential Guard smoke test](rdp_remote_credential_guard_smoke_test.md)
- Lints: `vauban-proxy-rdp/scripts/check_patch_pins.sh`,
  `vauban-proxy-rdp/tests/patch_pins_invariants_test.rs`

In the commands below, `OLD` is the commit the workspace pins today and
`NEW` the one it moves to, both as full 40-character ids.

## 1. Before touching the manifest

- [ ] Note `OLD`: the `rev` of the `ironrdp-*` entries under
      `[patch.crates-io]` in the workspace `Cargo.toml`.
- [ ] Choose `NEW` as a commit of the `master` branch of
      `https://github.com/Devolutions/IronRDP`, never a branch name or a
      tag.
- [ ] Get both commits in a clone kept outside the Vauban tree:

```bash
git clone https://github.com/Devolutions/IronRDP ironrdp-upstream
```

- [ ] Read what changed between the two, for the crates the proxy
      resolves:

```bash
git -C ironrdp-upstream log --oneline OLD..NEW -- crates/ironrdp-connector crates/ironrdp-rdpear crates/ironrdp-session crates/ironrdp-pdu crates/ironrdp-dvc crates/ironrdp-svc
```

- [ ] Check whether a published IronRDP release now contains Remote
      Credential Guard (`ironrdp-rdpear` on crates.io, and a connector
      release whose `sspi` has the `rcg` module). If so, the patch
      entries can go: see section 7 before continuing.

## 2. The redirection channel backend

`vauban-proxy-rdp/src/remote_guard_channel.rs` is an adapted copy of
`crates/ironrdp-connector/src/remote_guard.rs`. Compare upstream with
itself, not upstream with the copy: the copy differs on purpose, and a
direct diff is mostly noise.

- [ ] Diff the upstream module between the two commits:

```bash
git -C ironrdp-upstream diff OLD..NEW -- crates/ironrdp-connector/src/remote_guard.rs
```

- [ ] Diff the crate that defines the channel and its NDR types:

```bash
git -C ironrdp-upstream diff OLD..NEW -- crates/ironrdp-rdpear
```

- [ ] An empty first diff means the copy needs no change. Tick the rest
      of this section as not applicable, and still do the second diff:
      a changed NDR type breaks the copy at compile time, a changed
      encoding does not.

For each hunk of the first diff, decide with this table, and apply the
change by hand to the copy:

| Upstream change | Action on the copy |
|---|---|
| Fix in the framing: lengths, wrap overhead, call identifiers, package names, NDR profile | Port it. |
| Fix or addition in the handling of a Kerberos operation (`execute`) | Port it, keeping the `PDU_*` slot on every `asn1_output`. |
| New Kerberos operation, or new field of a request or response | Port it. Find the slot of each ASN.1 buffer it returns before merging (see below). |
| Change of a status code returned to the target | Port it, then re-read `operation_status` against the policy refusals of `remote_guard.rs`. |
| NTLM operations implemented or extended | Do not port. Redirected NTLM stays refused. |
| `KERB_ASN1_DATA.Pdu` now set upstream | Compare value by value with the `PDU_*` constants. A difference is a finding to settle on a real target, not a value to adopt. |
| Constructor, connector wiring, feature gates | Ignore. The proxy attaches the channel itself in `session.rs`. |
| Renames, formatting, comments | Ignore, unless a comment documents behaviour of the target. |

Three differences are deliberate. After the port, confirm each is still
there:

- [ ] Every ASN.1 buffer returned to the target carries its slot
      (`PDU_ENCRYPTED_DATA`, `PDU_ENCRYPTED_DATA_SHIFTED`,
      `PDU_CHECKSUM`, `PDU_ENC_AP_REP_PART`, or the slot echoed from the
      request). No call of `asn1_output` passes a literal 0, and the
      test `attack_no_response_slot_is_zero` lists every constant a
      response can carry. A target that receives slot 0 rejects every
      response and repeats its requests without end.
- [ ] `ntlm_available` answers `false` and `execute_ntlm` refuses.
- [ ] The module has no constructor that takes a connector, and the
      proxy still does not enable the connector's `remote-guard`
      feature (rule 6 of `check_patch_pins.sh`).

A new ASN.1 buffer needs a slot. The slot is the index of the type in
the Kerberos module compiled into the target; it is not in
[MS-RDPEAR]. Take it from the rdpear channel of FreeRDP, record the
source in the comment of the new constant, and add a unit test next to
the three existing ones. Without a source, do not guess: leave the
operation refused and note it in the known limits of the Kerberos modes
document.

- [ ] If the copy changed, update the "Origin" paragraph of its header
      only if one of the three differences changed.
- [ ] If upstream now sets the slots, takes a caller-supplied policy
      and no longer needs the DNS resolver, the copy can be retired:
      section 7.

## 3. Other code derived from private upstream items

`encode_rtt_response` in `vauban-proxy-rdp/src/session.rs` mirrors
`respond_to_connect_time_autodetect`, private in `ironrdp-connector`.
The proxy answers the connect-time RTT request itself, through its own
demultiplexer.

- [ ] Diff the upstream function between the two commits, and port a
      change of the answer it encodes:

```bash
git -C ironrdp-upstream diff OLD..NEW -- crates/ironrdp-connector/src/connection.rs
```

- [ ] `test_upstream_connector_survives_interleaved_autodetect_without_demux`
      still passes. A failure means `NEW` lost the upstream fix and the
      local demultiplexer is load-bearing again: do not retire it.
- [ ] Search the proxy for any other such item added since this
      checklist was written, and add it here:

```bash
git grep -n -i -E 'adapted from|mirrors the upstream|ported from|private in' -- vauban-proxy-rdp
```

## 4. Moving the pin

Every occurrence moves in the same commit. `check_patch_pins.sh`
refuses two different revs.

- [ ] Workspace `Cargo.toml`: the `rev` of every `ironrdp-*` entry
      under `[patch.crates-io]`, and the commit named in the comment
      above them.
- [ ] `vauban-proxy-rdp/Cargo.toml`: the `rev` of `ironrdp-rdpear`.
- [ ] `vauban-proxy-rdp/Cargo.toml`: the version of each `ironrdp-*`
      dependency, if upstream raised the one it declares. A version
      that no longer matches makes Cargo ignore the patch entry and
      take the crate from crates.io, with a warning and no error.
- [ ] `vauban-proxy-rdp/tests/patch_pins_invariants_test.rs`:
      `IRONRDP_REV`.
- [ ] A crate upstream added and the proxy now resolves gets its own
      patch entry, on the same rev.

Then check what the move brought with it:

- [ ] No warning `Patch ... was not used in the crate graph`. The
      command must print nothing:

```bash
cargo check -p vauban-proxy-rdp 2>&1 | grep -i 'was not used'
```

- [ ] One line per `ironrdp-*` crate, every one from the git source at
      `NEW`. A crate listed twice, or one without the repository after
      its version, came from crates.io:

```bash
cargo tree -p vauban-proxy-rdp --prefix none | grep '^ironrdp-' | sed 's/ (\*)$//' | sort -u
```

- [ ] The version of `sspi`, and where it comes from. It must come from
      crates.io; a `[patch.crates-io]` entry for it is refused (rule 4).
      If the version changed, read its changelog for `credssp`,
      `kerberos` and `rcg`, and re-read the comment of
      `test_support/windows_mic.rs`:

```bash
cargo tree -p vauban-proxy-rdp -i sspi | head -5
```

- [ ] No DNS resolver in the tree. Both commands must print an error
      saying the package is not found:

```bash
cargo tree -p vauban-proxy-rdp -i hickory-resolver
```

```bash
cargo tree -p vauban-proxy-rdp -i hickory-proto
```

- [ ] `picky-krb` in `vauban-proxy-rdp/Cargo.toml` still matches the
      version `sspi` resolves.

## 5. Automated gates

- [ ] `just lint` (runs `check_patch_pins.sh` and `just deny`).
- [ ] A new advisory is handled on its merits. An exemption in
      `deny.toml` is dated and says why no fix is available. The
      existing exemptions that name `ironrdp` or `sspi` are re-read:
      remove the ones the new tree no longer needs.
- [ ] `just validate`. It uses the shared test database: no other run
      at the same time.

## 6. Manual validation

CI cannot cover a Windows target accepting a logon.

- [ ] [IronRDP upgrade smoke test](ironrdp_migration_smoke_test.md),
      in full.
- [ ] [Remote Credential Guard smoke test](rdp_remote_credential_guard_smoke_test.md),
      in full, if section 2 changed the copy, if `ironrdp-rdpear`
      changed, or if the version of `sspi` changed. Otherwise its
      sections on the logon and on one redirected operation are
      enough.
- [ ] Record the policy the pass ran under
      (`remote_guard_outbound_identity`: `deny`, `allow`, or both) and
      the Kerberos module of the target (the one up to Server 2022, or
      the one of Windows 11 24H2 and Server 2025).

## 7. When the pin or the copy can go

Two separate exits. Neither needs the other.

**The patch entries go** when a published IronRDP release contains
Remote Credential Guard:

- [ ] Remove the `ironrdp-*` entries and their comment from
      `[patch.crates-io]`, and take `ironrdp-rdpear` from crates.io.
- [ ] Remove rules 2, 3 and 5 of `check_patch_pins.sh` and their tests.
      Keep rules 1, 4 and 6.
- [ ] Update `docs/THIRD_PARTY_LICENSES.md` and the "IronRDP from its
      main branch" paragraph of the RDP Architecture document.

**The copy goes** only when the upstream backend does all of this:

- [ ] sets `KERB_ASN1_DATA.Pdu` to the values of the `PDU_*` constants,
      for both Kerberos modules;
- [ ] lets the caller supply the context that executes the operations,
      so `PolicyContext` (deny or allow, loop guard, logging) stays in
      front of every one;
- [ ] comes without `sspi`'s `dns_resolver` feature.

Then delete `remote_guard_channel.rs`, move its three unit tests to
tests of the upstream backend's output, drop rule 6, and update the
header of `remote_guard.rs`, `docs/THIRD_PARTY_LICENSES.md` and the two
RDP documents.

## 8. Record

- [ ] Add a row to the known-good table of each smoke test that was
      run: date, short commit of IronRDP, version of `sspi`, version of
      the proxy, what was covered. Describe the target by its Kerberos
      module, with example names only.
- [ ] `docs/technical`: amend the RDP Architecture and Kerberos modes
      documents if behaviour, a failure reason or a known limit
      changed.
- [ ] One commit for the pin and the ports it required,
      `build(rdp): move IronRDP to <short NEW>`. Its body lists what was
      ported into the copy and what was deliberately left out.
