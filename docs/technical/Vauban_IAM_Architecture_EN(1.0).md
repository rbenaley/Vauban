# Vauban IAM Architecture

**Version:** 1.0  
**Date:** 15 March 2026  
**Author:** Richard Ben Aleya

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [Authentication Service (vauban-auth)](#3-authentication-service-vauban-auth)
4. [Access Control Service (vauban-access)](#4-access-control-service-vauban-access)
5. [RBAC Layer: Casbin Policy Engine](#5-rbac-layer-casbin-policy-engine)
6. [Instance-Level Access Control](#6-instance-level-access-control)
7. [Database Schema](#7-database-schema)
8. [IPC Protocol](#8-ipc-protocol)
9. [Web Integration](#9-web-integration)
10. [Capsicum Sandboxing](#10-capsicum-sandboxing)
11. [Configuration](#11-configuration)
12. [Security Analysis](#12-security-analysis)
13. [Testing Strategy](#13-testing-strategy)
14. [Architecture Decisions](#14-architecture-decisions)

---

## 1. Introduction

### 1.1 Background

Prior to version 0.3.0, Vauban handled authentication and authorization inline within `vauban-web`:

- **Password hashing** (Argon2id) ran inside the web process, exposing cryptographic material to the same address space as HTTPS handlers.
- **Role checks** were hardcoded `is_superuser` / `is_staff` guards scattered across handlers, with no centralized policy engine.
- **Access control** was coarse-grained: users either had access to all assets or none, with no per-protocol or per-asset-group granularity.

### 1.2 Motivation for Change

The migration was driven by three goals:

1. **Privilege Separation**: Move security-critical operations (password hashing, authorization decisions) into dedicated sandboxed processes, following the OpenSSH privsep model documented in [Vauban_Privsep_Architecture_EN(1.2).md](Vauban_Privsep_Architecture_EN(1.2).md).

2. **Centralized Policy Engine**: Replace inline role guards with a Casbin-based RBAC engine that enforces a single policy file, making authorization auditable and configurable without code changes.

3. **Instance-Level Access Control**: Introduce fine-grained authorization linking user groups to asset groups with per-protocol granularity, time-based validity windows, MFA requirements, and priority-based evaluation.

### 1.3 Evolution Timeline

| Version | Milestone | Scope |
|---------|-----------|-------|
| 0.2.x | Inline auth and role checks | All in `vauban-web` |
| 0.3.0 | Dedicated `vauban-auth` and `vauban-rbac` services | Privsep for auth + Casbin RBAC |
| 0.4.0 | Rename `vauban-rbac` to `vauban-access`, add instance-level rules, DB isolation | Full IAM architecture |

### 1.4 Related Documents

- [Vauban_Privsep_Architecture_EN(1.2).md](Vauban_Privsep_Architecture_EN(1.2).md) -- Pipe topology, Capsicum sandboxing, supervisor architecture
- [Vauban_Vault_Architecture_EN(1.0).md](Vauban_Vault_Architecture_EN(1.0).md) -- Secrets management (MFA secrets, credential encryption)
- [Vauban_RDP_Architecture_EN(1.0).md](Vauban_RDP_Architecture_EN(1.0).md) -- RDP proxy implementation

---

## 2. Architecture Overview

### 2.1 Two-Layer Authorization Model

Vauban implements a **dual-layer** authorization model:

```mermaid
flowchart TB
    Decision["Authorization Decision"]
    Decision --> L1
    Decision --> L2

    subgraph L1 ["Layer 1: RBAC (Casbin)"]
        R1["Feature-level<br/><i>Can this role manage users?</i>"]
    end

    subgraph L2 ["Layer 2: Instance-Level Rules"]
        R2["Asset-level<br/><i>Can this user SSH to server X?</i>"]
    end
```

| Layer | Engine | Scope | Example |
|-------|--------|-------|---------|
| **RBAC** | Casbin (model.conf + policy.csv) | Feature access | "Can `role:staff` write `users`?" |
| **Instance-Level** | SQL-based rules (access_rules table) | Asset access | "Can user 42 SSH to asset group 'Production'?" |

Both layers are evaluated by a single service (`vauban-access`), which owns all authorization state and exposes it exclusively via IPC.

### 2.2 Service Responsibilities

```mermaid
flowchart TB
    subgraph auth_service [vauban-auth - UID 904]
        A["Password Hashing<br/>Argon2id verify/hash"]
    end

    subgraph access_service [vauban-access - UID 903]
        R["RBAC Engine<br/>Casbin Enforcer"]
        AC["Instance-Level<br/>Access Rules"]
        DB_AC[(Access DB Pool)]
    end

    subgraph web [vauban-web - UID 907]
        W["HTTP Handlers<br/>API + Web UI"]
        AUTH_C["AuthIpcClient"]
        ACC_C["AccessIpcClient"]
    end

    W --> AUTH_C
    W --> ACC_C
    AUTH_C -->|"IPC pipe"| A
    ACC_C -->|"IPC pipe: RbacCheck"| R
    ACC_C -->|"IPC pipe: AccessRequest"| AC
    AC --> DB_AC
```

| Service | UID/GID | Responsibilities | Database |
|---------|---------|-----------------|----------|
| `vauban-auth` | 904/904 | Argon2id password hashing and verification | None (stateless) |
| `vauban-access` | 903/903 | Casbin RBAC + instance-level access rules | Dedicated pool (4 connections) |

### 2.3 IPC Topology

Both services participate in the supervisor's pipe topology:

| Pipe | Direction | Purpose |
|------|-----------|---------|
| `web` <-> `auth` | Bidirectional | Password verify/hash requests |
| `web` <-> `access` | Bidirectional | RBAC checks + access rule CRUD + access evaluation |
| `auth` <-> `access` | Bidirectional | Role verification during authentication (future) |
| `proxy-ssh` <-> `access` | Bidirectional | Session authorization before SSH connect |
| `proxy-rdp` <-> `access` | Bidirectional | Session authorization before RDP connect |

---

## 3. Authentication Service (vauban-auth)

### 3.1 Purpose

`vauban-auth` is a **synchronous, sandboxed service** dedicated to password hashing. By isolating Argon2id operations in a separate process:

- The web process never touches plaintext passwords or hash parameters.
- A compromise of `vauban-web` does not expose the hashing capability.
- Argon2id CPU/memory-intensive operations do not block the async web server.

### 3.2 Supported Operations

| Operation | Request Message | Response Message | Description |
|-----------|----------------|------------------|-------------|
| Verify password | `AuthVerifyPassword` | `AuthVerifyPasswordResponse` | Compare plaintext against stored Argon2id hash |
| Hash password | `AuthHashPassword` | `AuthHashPasswordResponse` | Generate new Argon2id hash from plaintext |
| Authenticate user | `AuthRequest` | `AuthResponse` | Full authentication flow (future: SSO, LDAP) |
| Verify MFA | `MfaVerify` | `MfaVerifyResponse` | TOTP/HOTP code verification (future) |

### 3.3 Argon2id Configuration

Parameters are injected by the supervisor via environment variables before sandbox entry:

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Memory cost | `VAUBAN_ARGON2_MEMORY_KB` | 19,456 KB (~19 MB) | Memory usage per hash |
| Iterations | `VAUBAN_ARGON2_ITERATIONS` | 2 | Time cost (number of passes) |
| Parallelism | `VAUBAN_ARGON2_PARALLELISM` | 1 | Degree of parallelism |

These defaults follow the OWASP minimum recommendations for Argon2id. Production deployments typically increase `memory_size_kb` to 65,536 KB (64 MB) via `config/default.toml`.

### 3.4 Password Verification Flow

```mermaid
sequenceDiagram
    participant W as vauban-web
    participant A as vauban-auth

    W->>A: AuthVerifyPassword(request_id, password_hash, password)
    Note over A: Parse stored Argon2id hash
    Note over A: Verify password against hash
    A->>W: AuthVerifyPasswordResponse(request_id, valid: bool)
```

The `password` field uses `SensitiveString`, which:
- Zeroizes backing memory on drop (prevents credential remnants)
- Redacts output in Debug formatting (`[REDACTED]`)
- Is serde-transparent for bincode serialization compatibility

### 3.5 Password Hashing Flow

```mermaid
sequenceDiagram
    participant W as vauban-web
    participant A as vauban-auth

    W->>A: AuthHashPassword(request_id, password)
    Note over A: Generate random salt (OsRng)
    Note over A: Hash with Argon2id (configured params)
    A->>W: AuthHashPasswordResponse(request_id, hash, error)
```

### 3.6 Service Architecture

```rust
// Core service state
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    shutdown_requested: bool,
    argon2_params: Argon2Params,
}
```

The service follows the standard Vauban synchronous service pattern:

1. **Read environment** -- IPC FDs, Argon2 params, topology channels
2. **Clear environment** -- Remove all env vars before sandbox entry
3. **Enter Capsicum sandbox** -- `cap_enter()` on FreeBSD
4. **Main loop** -- `poll(2)` on supervisor + peer channels, dispatch messages

### 3.7 Dependencies

| Crate | Purpose |
|-------|---------|
| `argon2 0.5` | Argon2id password hashing |
| `rand 0.8` | Cryptographic salt generation (OsRng) |
| `shared` | IPC channel, messages, Capsicum wrappers |

`vauban-auth` has **no database dependency** and **no async runtime**. It is purely synchronous and stateless.

---

## 4. Access Control Service (vauban-access)

### 4.1 Purpose

`vauban-access` (formerly `vauban-rbac`) is the **centralized authorization service**. It handles two distinct concerns:

1. **Feature-level RBAC** via the Casbin policy engine (role-based checks like "can this role manage users?")
2. **Instance-level access rules** via SQL queries against its dedicated database (asset-level checks like "can this user SSH to this asset group?")

### 4.2 Evolution from vauban-rbac

| Aspect | v0.3.0 (vauban-rbac) | v0.4.0 (vauban-access) |
|--------|---------------------|----------------------|
| Name | `vauban-rbac` | `vauban-access` |
| Service enum | `Service::Rbac` | `Service::Access` |
| Config section | `[rbac]` | `[access]` |
| Config directory | `config/rbac/` | `config/access/` |
| Capabilities | Casbin RBAC only | Casbin RBAC + instance-level access rules |
| Database | None | Dedicated pool (4 connections) |
| Tables owned | None | `access_rules`, `vauban_groups`, `asset_groups`, `user_groups` |
| IPC messages | `RbacCheck` / `RbacResponse` | `RbacCheck` + 24 `AccessRequest` + 15 `AccessResponse` variants |

### 4.3 Dual-Engine Architecture

```mermaid
flowchart TB
    subgraph vauban_access [vauban-access]
        direction TB

        MSG[Message Router]

        subgraph casbin [Casbin Engine]
            E["Enforcer<br/>model.conf + policy.csv"]
        end

        subgraph sql_engine [SQL Engine]
            H["Handler Dispatch"]
            DB[(PostgreSQL Pool)]
        end

        MSG -->|RbacCheck| E
        MSG -->|AccessRequest| H
        H --> DB
    end
```

### 4.4 Service State

```rust
struct ServiceState {
    start_time: Instant,
    requests_processed: u64,
    requests_failed: u64,
    draining: bool,
    shutdown_requested: bool,
    enforcer: Option<Enforcer>,           // Casbin policy engine
    db_pool: Option<db::DbPool>,          // Async PG pool (diesel-async)
    rt: Option<tokio::runtime::Runtime>,  // Single-threaded Tokio RT
}
```

Unlike `vauban-auth`, `vauban-access` requires a **minimal Tokio runtime** (`current_thread`) because `diesel-async` requires an async executor for database queries. This runtime is created once at startup and used via `rt.block_on()` in the synchronous main loop.

### 4.5 Startup Sequence

```mermaid
sequenceDiagram
    participant S as vauban-supervisor
    participant A as vauban-access

    S->>A: fork + exec (env vars set)
    Note over A: 1. Read IPC FDs from env
    Note over A: 2. Read VAUBAN_ACCESS_MODEL_PATH
    Note over A: 3. Read VAUBAN_ACCESS_POLICY_PATH
    Note over A: 4. Read VAUBAN_DATABASE_URL
    Note over A: 5. Read topology channels (WEB)
    Note over A: 6. Clear all env vars
    Note over A: 7. Load Casbin enforcer (file I/O)
    Note over A: 8. Create Tokio runtime (current_thread)
    Note over A: 9. Create DB pool + force all connections
    Note over A: 10. Enter Capsicum sandbox
    Note over A: 11. Start poll-based main loop
```

### 4.6 Dependencies

| Crate | Purpose |
|-------|---------|
| `casbin` | RBAC policy engine |
| `diesel` + `diesel-async` | PostgreSQL ORM (async) |
| `deadpool` | Connection pool management |
| `tokio` (rt feature only) | Minimal async runtime for diesel-async |
| `chrono`, `uuid` | Timestamp and UUID handling |
| `shared` | IPC channel, messages, Capsicum wrappers |

---

## 5. RBAC Layer: Casbin Policy Engine

### 5.1 Model Definition

The Casbin model uses a standard RBAC pattern with wildcards:

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && (p.obj == "*" || r.obj == p.obj) && (p.act == "*" || r.act == p.act)
```

The matcher supports wildcard matching for both objects and actions, enabling the `superuser` role to have unrestricted access via a single policy line.

### 5.2 Default Policy

```csv
p, role:superuser, *, *
p, role:staff, users, read
p, role:staff, users, write
p, role:staff, assets, read
p, role:staff, assets, write
p, role:staff, sessions, read
p, role:staff, sessions, write
p, role:staff, groups, read
p, role:staff, groups, write
p, role:staff, access_rules, read
p, role:staff, access_rules, write
p, role:staff, admin, view
p, role:user, assets, read
p, role:user, sessions, read
p, role:user, sessions, create
p, role:user, profile, read
p, role:user, profile, write
```

### 5.3 Role Hierarchy

| Role | Capabilities | Typical Usage |
|------|-------------|---------------|
| `role:superuser` | Full access (`*, *`) | System administrators |
| `role:staff` | Manage users, assets, sessions, groups, access rules; view admin UI | IT operators |
| `role:user` | Read assets, read/create sessions, manage own profile | End users connecting to assets |

### 5.4 Evaluation Flow

```mermaid
sequenceDiagram
    participant W as vauban-web
    participant A as vauban-access

    W->>A: RbacCheck(request_id, "role:staff", "users", "write")
    Note over A: enforcer.enforce(["role:staff", "users", "write"])
    Note over A: Match: p, role:staff, users, write
    A->>W: RbacResponse(request_id, {allowed: true})
```

### 5.5 Fallback Behavior

When no Casbin enforcer is loaded (dev mode without supervisor):

| Build Mode | Behavior | Rationale |
|------------|----------|-----------|
| `debug_assertions` (dev) | Allow all requests | Developer convenience |
| Release | Deny all requests | Fail-closed security |

```rust
#[cfg(debug_assertions)]
{
    // Allow all in dev mode
    RbacResult { allowed: true, reason: None }
}
#[cfg(not(debug_assertions))]
{
    // Deny-by-default in production
    RbacResult { allowed: false, reason: Some("RBAC policy engine not configured") }
}
```

### 5.6 RBAC Integration Points

RBAC checks gate access to UI features and API endpoints:

| Resource | Actions | Used By |
|----------|---------|---------|
| `users` | `read`, `write` | User management (list, create, edit, delete) |
| `assets` | `read`, `write` | Asset management |
| `sessions` | `read`, `write`, `create` | Session listing, connection initiation |
| `groups` | `read`, `write` | Group management (vauban_groups, asset_groups) |
| `access_rules` | `read`, `write` | Access rule CRUD |
| `admin` | `view` | Admin sidebar visibility, dashboard |
| `profile` | `read`, `write` | User's own profile management |

---

## 6. Instance-Level Access Control

### 6.1 Concept

While RBAC controls *feature* access ("can this role manage users?"), instance-level access controls *asset* access ("can this specific user connect to this specific server via SSH?").

Access rules link **user groups** to **asset groups** with constraints:

```mermaid
flowchart LR
    UG["User Group<br/><b>DevOps Team</b><br/>(3 members)"]
    AR["Access Rule<br/><b>SSH + RDP</b><br/>MFA required<br/>9:00 - 18:00"]
    AG["Asset Group<br/><b>Production</b><br/>(12 servers)"]

    UG --- AR --- AG
```

### 6.2 Access Rule Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | varchar(100) | Human-readable rule name |
| `description` | text | Optional description |
| `user_group_id` | FK -> vauban_groups | Group of users this rule applies to |
| `asset_group_id` | FK -> asset_groups | Group of assets this rule grants access to |
| `allowed_protocols` | text[] | List of allowed protocols: `ssh`, `rdp`, `vnc` |
| `valid_from` | timestamptz | Start of validity window (NULL = no start constraint) |
| `valid_until` | timestamptz | End of validity window (NULL = no end constraint) |
| `require_mfa` | bool | Whether MFA is required for connections |
| `require_approval` | bool | Whether admin approval (JIT) is required before connection |
| `max_session_duration` | int | Maximum session duration in minutes (NULL = unlimited) |
| `is_active` | bool | Whether the rule is currently active |
| `priority` | int | Priority for conflict resolution (higher = more important) |

### 6.3 Evaluation Logic

When a user attempts to connect to an asset, `vauban-access` evaluates access by:

1. **Identify asset group**: The target asset belongs to an `asset_group`
2. **Find matching rules**: Query `access_rules` where:
   - The user is a member of the rule's `user_group` (via `user_groups` join table)
   - The rule's `asset_group_id` matches the target
   - The rule is active (`is_active = true`)
   - The current time falls within `[valid_from, valid_until]`
   - The requested protocol is in `allowed_protocols`
3. **Aggregate constraints**: If any matching rules exist, access is granted with the most restrictive constraints:
   - `require_mfa` = true if **any** matching rule requires MFA
   - `require_approval` = true if **any** matching rule requires approval
   - `max_session_duration` = **minimum** across all matching rules

```mermaid
flowchart TB
    Start[CheckAccess Request] --> FindRules["Query access_rules<br/>JOIN user_groups<br/>Filter: user, asset_group,<br/>protocol, active, time window"]

    FindRules --> Empty{Rules found?}
    Empty -->|No| Deny["AccessChecked<br/>allowed: false"]
    Empty -->|Yes| Aggregate["Aggregate constraints:<br/>any(require_mfa)<br/>any(require_approval)<br/>min(max_session_duration)"]
    Aggregate --> Allow["AccessChecked<br/>allowed: true<br/>+ constraints"]
```

### 6.4 Access Check SQL

The core evaluation query (simplified):

```sql
SELECT require_mfa, require_approval, max_session_duration
FROM access_rules
INNER JOIN user_groups ON user_groups.group_id = access_rules.user_group_id
WHERE user_groups.user_id = $1          -- the connecting user
  AND access_rules.asset_group_id = $2  -- the target asset group
  AND access_rules.is_active = true
  AND (valid_from IS NULL OR valid_from <= NOW())
  AND (valid_until IS NULL OR valid_until >= NOW())
  AND access_rules.allowed_protocols @> ARRAY[$3]  -- protocol filter
```

### 6.5 Accessible Groups Listing

For the asset list UI, `vauban-access` can return all asset groups a user has access to, along with the allowed protocols for each:

```mermaid
sequenceDiagram
    participant W as vauban-web
    participant A as vauban-access

    W->>A: AccessRequest::ListAccessibleGroups(user_id)
    Note over A: Query all active rules<br/>for user's groups
    Note over A: Aggregate by asset_group_id<br/>with protocol union
    A->>W: AccessResponse::AccessibleGroups([<br/>  {asset_group_id: 1, protocols: ["ssh", "rdp"]},<br/>  {asset_group_id: 3, protocols: ["ssh"]}<br/>])
```

This enables the web UI to filter the asset list, showing only assets the user can actually connect to, with the appropriate protocol buttons.

---

## 7. Database Schema

### 7.1 Table Ownership

`vauban-access` exclusively owns four tables that can optionally reside in a **separate PostgreSQL instance** from `vauban-web`:

```mermaid
erDiagram
    vauban_groups ||--o{ user_groups : "has members"
    vauban_groups ||--o{ access_rules : "user_group_id"
    asset_groups ||--o{ access_rules : "asset_group_id"
    users ||--o{ user_groups : "user_id"

    vauban_groups {
        int id PK
        uuid uuid UK
        varchar name
        text description
        varchar source
        varchar external_id
        int parent_id FK
        timestamptz last_synced
        timestamptz created_at
        timestamptz updated_at
    }

    user_groups {
        int user_id PK_FK
        int group_id PK_FK
    }

    asset_groups {
        int id PK
        uuid uuid UK
        varchar name
        varchar slug UK
        text description
        varchar color
        varchar icon
        int parent_id FK
        bool is_deleted
        timestamptz created_at
        timestamptz updated_at
    }

    access_rules {
        int id PK
        uuid uuid UK
        varchar name
        text description
        int user_group_id FK
        int asset_group_id FK
        text_array allowed_protocols
        timestamptz valid_from
        timestamptz valid_until
        bool require_mfa
        bool require_approval
        int max_session_duration
        bool is_active
        int priority
        timestamptz created_at
        timestamptz updated_at
    }
```

### 7.2 Database Separation

The FK from `assets.group_id` to `asset_groups(id)` was deliberately dropped (migration `20260312000000_drop_asset_group_fk`) to enable running `vauban-access` against a separate PostgreSQL instance:

```sql
-- Enable DB separation: referential integrity enforced at application/IPC level
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_group_id_fkey;
```

This design allows:
- `vauban-web` to have its own database with user/asset/session tables
- `vauban-access` to have a dedicated database with group/rule tables
- Cross-references resolved via IPC rather than SQL JOINs

### 7.3 vauban_groups (User Groups)

User groups support both local and external sources:

| Field | Description |
|-------|-------------|
| `source` | `"local"` for manually created groups, or `"ldap"`, `"oidc"` for synced groups |
| `external_id` | Original identifier in the external directory |
| `last_synced` | Timestamp of the last directory sync |
| `parent_id` | Hierarchical group nesting (future) |

### 7.4 access_rules Indexes

```sql
CREATE INDEX idx_access_rules_uuid ON access_rules(uuid);
CREATE INDEX idx_access_rules_user_group ON access_rules(user_group_id);
CREATE INDEX idx_access_rules_asset_group ON access_rules(asset_group_id);
CREATE INDEX idx_access_rules_active ON access_rules(is_active) WHERE is_active = true;
```

The partial index on `is_active` optimizes the most frequent query pattern (evaluating active rules during connection attempts).

---

## 8. IPC Protocol

### 8.1 Authentication Messages

```rust
// Web -> Auth: Verify a password against a stored hash
AuthVerifyPassword {
    request_id: u64,
    password_hash: String,         // Stored Argon2id hash
    password: SensitiveString,     // Plaintext password (zeroized on drop)
}
AuthVerifyPasswordResponse {
    request_id: u64,
    valid: bool,
}

// Web -> Auth: Hash a new password
AuthHashPassword {
    request_id: u64,
    password: SensitiveString,
}
AuthHashPasswordResponse {
    request_id: u64,
    hash: Option<String>,          // Argon2id hash string
    error: Option<String>,
}

// Web -> Auth: Full authentication (future: SSO, LDAP)
AuthRequest {
    request_id: u64,
    username: String,
    credential: Vec<u8>,
    source_ip: IpAddr,
}
AuthResponse {
    request_id: u64,
    result: AuthResult,            // Success | Failure | MfaRequired
}

// Web -> Auth: MFA verification (future)
MfaVerify {
    request_id: u64,
    challenge_id: String,
    code: String,
}
MfaVerifyResponse {
    request_id: u64,
    success: bool,
    session_id: Option<String>,
}
```

### 8.2 RBAC Messages

```rust
// Web/Proxy -> Access: Feature-level authorization check
RbacCheck {
    request_id: u64,
    subject: String,   // e.g., "role:staff"
    object: String,    // e.g., "users"
    action: String,    // e.g., "write"
}
RbacResponse {
    request_id: u64,
    result: RbacResult {
        allowed: bool,
        reason: Option<String>,
    },
}
```

### 8.3 Access Control Messages

The `AccessRequest` enum contains **24 variants** and `AccessResponse` contains **15 variants**, organized into five categories:

#### Evaluation

| Request | Response | Description |
|---------|----------|-------------|
| `CheckAccess { user_id, asset_group_id, protocol }` | `AccessChecked(AccessCheckResult)` | Evaluate if a user can access an asset group with a protocol |
| `ListAccessibleGroups { user_id }` | `AccessibleGroups(Vec<AccessibleGroupEntry>)` | List all accessible asset groups for a user |

#### Access Rule CRUD

| Request | Response | Description |
|---------|----------|-------------|
| `CreateAccessRule { data }` | `AccessRule(Result<AccessRuleInfo, String>)` | Create a new access rule |
| `GetAccessRule { uuid }` | `AccessRule(Result<AccessRuleInfo, String>)` | Get rule by UUID |
| `ListAccessRules` | `AccessRuleList(Vec<AccessRuleInfo>)` | List all rules |
| `UpdateAccessRule { uuid, data }` | `AccessRule(Result<AccessRuleInfo, String>)` | Update existing rule |
| `DeleteAccessRule { uuid }` | `Deleted(Result<(), String>)` | Delete rule |

#### User Group CRUD

| Request | Response | Description |
|---------|----------|-------------|
| `CreateVaubanGroup { name, description }` | `VaubanGroup(Result<VaubanGroupInfo, String>)` | Create user group |
| `GetVaubanGroup { uuid }` | `VaubanGroup(Result<VaubanGroupInfo, String>)` | Get group by UUID |
| `GetVaubanGroupById { id }` | `VaubanGroup(Result<VaubanGroupInfo, String>)` | Get group by integer ID |
| `ListVaubanGroups` | `VaubanGroupList(Vec<VaubanGroupInfo>)` | List all user groups |
| `UpdateVaubanGroup { uuid, name, description }` | `VaubanGroup(Result<VaubanGroupInfo, String>)` | Update group |
| `DeleteVaubanGroup { uuid }` | `Deleted(Result<(), String>)` | Delete group |

#### Group Membership

| Request | Response | Description |
|---------|----------|-------------|
| `AddGroupMember { group_id, user_id }` | `Ok` | Add user to group |
| `RemoveGroupMember { group_id, user_id }` | `Ok` | Remove user from group |
| `ListGroupMembers { group_id }` | `MemberList(Vec<i32>)` | List member user IDs |
| `ListUserGroups { user_id }` | `UserGroupList(Vec<VaubanGroupInfo>)` | List groups for a user |

#### Asset Group CRUD

| Request | Response | Description |
|---------|----------|-------------|
| `CreateAssetGroup { name, slug, description, color, icon }` | `AssetGroup(Result<AssetGroupInfo, String>)` | Create asset group |
| `GetAssetGroup { uuid }` | `AssetGroup(Result<AssetGroupInfo, String>)` | Get asset group |
| `ListAssetGroups` | `AssetGroupList(Vec<AssetGroupInfo>)` | List all asset groups |
| `UpdateAssetGroup { uuid, ... }` | `AssetGroup(Result<AssetGroupInfo, String>)` | Update asset group |
| `DeleteAssetGroup { uuid }` | `Deleted(Result<(), String>)` | Delete asset group |
| `GetGroupOptions` | `GroupOptions { user_groups, asset_groups }` | Minimal lists for form dropdowns |

### 8.4 Data Types

```rust
/// Result of an instance-level access check.
pub struct AccessCheckResult {
    pub allowed: bool,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
}

/// Full info about an access rule.
pub struct AccessRuleInfo {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub user_group_id: i32,
    pub user_group_uuid: String,
    pub user_group_name: String,
    pub asset_group_id: i32,
    pub asset_group_uuid: String,
    pub asset_group_name: String,
    pub allowed_protocols: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub require_mfa: bool,
    pub require_approval: bool,
    pub max_session_duration: Option<i32>,
    pub is_active: bool,
    pub priority: i32,
    pub created_at: String,
    pub updated_at: String,
}

/// Info about a user group.
pub struct VaubanGroupInfo {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub source: String,          // "local", "ldap", "oidc"
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_synced: Option<String>,
    pub member_count: i64,
}

/// Info about an asset group.
pub struct AssetGroupInfo {
    pub id: i32,
    pub uuid: String,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub color: String,
    pub icon: String,
    pub created_at: String,
    pub updated_at: String,
}
```

---

## 9. Web Integration

### 9.1 IPC Clients

`vauban-web` communicates with auth and access services via async IPC clients that bridge the Tokio-based web server with synchronous pipe-based services.

#### AuthIpcClient

```rust
// Usage in login handler
let valid = state.auth_client
    .verify_password(password, &user.password_hash)
    .await?;

// Usage in user creation/password change
let hash = state.auth_client
    .hash_password(new_password)
    .await?;
```

#### AccessIpcClient

```rust
// RBAC check in handler middleware
let allowed = state.access_client
    .check_permission("role:staff", "users", "write")
    .await?;

// Instance-level access check before SSH/RDP connection
let result = state.access_client
    .check_access(user_id, asset_group_id, "ssh")
    .await?;

// Access rule CRUD (delegated to vauban-access)
let rules = state.access_client
    .list_access_rules()
    .await?;
```

### 9.2 IPC Client Architecture

Both clients follow the same pattern:

```mermaid
flowchart LR
    subgraph web [vauban-web - Tokio]
        H["HTTP Handler"] -->|"1. Send request"| C["IpcClient"]
        C -->|"2. Register oneshot"| PM["Pending Map<br/>request_id -> oneshot::Sender"]
        C -->|"3. Write to pipe"| P["IPC Pipe (write)"]
    end

    subgraph service [vauban-auth / vauban-access]
        S["Service Main Loop"]
    end

    P -->|"4. Request"| S
    S -->|"5. Response"| PR["IPC Pipe (read)"]

    subgraph web2 [vauban-web - Background Task]
        PR -->|"6. Read response"| BG["process_incoming()"]
        BG -->|"7. Resolve oneshot"| PM
    end

    PM -->|"8. Receive result"| H
```

Key design elements:
- **Request/response correlation** via monotonically increasing `request_id`
- **Async bridging** via `tokio::sync::oneshot` channels
- **Non-blocking pipe I/O** via `tokio::io::unix::AsyncFd`
- **Background task** (`process_incoming()`) continuously reads the pipe and dispatches responses

### 9.3 SQL Fallback

When IPC clients are unavailable (dev/test mode without supervisor), `vauban-web` falls back to direct SQL access:

| Operation | With IPC | Without IPC (fallback) |
|-----------|----------|----------------------|
| Password verify | `AuthIpcClient::verify_password()` | Local `argon2::verify_password()` |
| Password hash | `AuthIpcClient::hash_password()` | Local `argon2::hash_password()` |
| RBAC check | `AccessIpcClient::check_permission()` | Debug: allow all / Release: deny all |
| Access check | `AccessIpcClient::check_access()` | Direct SQL query against local DB |
| Access rule CRUD | `AccessIpcClient::create_access_rule()` etc. | Direct SQL via Diesel ORM |

This dual-path design enables:
- **Development** without running the full supervisor topology
- **Testing** with direct database access
- **Production** with full IPC privilege separation

### 9.4 Asset List Filtering

The web UI filters the asset list based on instance-level access:

```mermaid
sequenceDiagram
    participant U as User Browser
    participant W as vauban-web
    participant A as vauban-access
    participant DB as PostgreSQL (web)

    U->>W: GET /assets/
    W->>A: AccessRequest::ListAccessibleGroups(user_id)
    A->>W: AccessibleGroups([{group_id: 1, protocols: ["ssh"]}, ...])
    W->>DB: SELECT * FROM assets WHERE group_id IN (1, ...)
    W->>U: Asset list (only accessible assets, with protocol buttons)
```

Superusers and staff see all assets; regular users see only assets in groups they have access to via active access rules.

### 9.5 CSRF Protection

Access rule forms use the Alpine.js double-submit cookie pattern for CSRF protection:

1. Server generates a CSRF token and sets it as a cookie
2. Alpine.js reads the cookie and includes the token in the form submission
3. Server validates that the form token matches the cookie token

---

## 10. Capsicum Sandboxing

### 10.1 vauban-auth Sandbox

`vauban-auth` has the simplest sandbox profile:

| Resource | Capability Rights |
|----------|------------------|
| Supervisor IPC (read) | `CAP_READ`, `CAP_EVENT` |
| Supervisor IPC (write) | `CAP_WRITE` |
| Web peer IPC (read) | `CAP_READ`, `CAP_EVENT` |
| Web peer IPC (write) | `CAP_WRITE` |

No database, no file system, no network. After `cap_enter()`, the process can only hash passwords and communicate via its pre-opened IPC pipes.

### 10.2 vauban-access Sandbox

`vauban-access` has a slightly more complex profile due to its database requirement:

| Resource | Capability Rights |
|----------|------------------|
| Supervisor IPC (read) | `CAP_READ`, `CAP_EVENT` |
| Supervisor IPC (write) | `CAP_WRITE` |
| Web peer IPC (read) | `CAP_READ`, `CAP_EVENT` |
| Web peer IPC (write) | `CAP_WRITE` |
| Database socket | `CAP_READ`, `CAP_WRITE`, `CAP_CONNECT` |

All 4 database connections are pre-established before `cap_enter()`. If a connection is lost post-sandbox, it cannot be re-established.

### 10.3 Pre-Sandbox Resource Loading

Both services load all configuration before entering the sandbox:

| Resource | When Loaded | Service |
|----------|------------|---------|
| Argon2 parameters | From env vars at startup | `vauban-auth` |
| Casbin model + policy files | `DefaultModel::from_file()` before `cap_enter()` | `vauban-access` |
| Database connections | `force_create_all_connections()` before `cap_enter()` | `vauban-access` |
| IPC pipe FDs | From env vars at startup | Both |

---

## 11. Configuration

### 11.1 Supervisor Configuration

The supervisor injects configuration via environment variables at service spawn time:

#### Auth Service Environment

| Variable | Source | Default |
|----------|--------|---------|
| `VAUBAN_IPC_READ` | Supervisor pipe FD | Required |
| `VAUBAN_IPC_WRITE` | Supervisor pipe FD | Required |
| `VAUBAN_WEB_IPC_READ` | Topology channel FD | Optional |
| `VAUBAN_WEB_IPC_WRITE` | Topology channel FD | Optional |
| `VAUBAN_ARGON2_MEMORY_KB` | `[auth].argon2_memory_kb` | 19456 |
| `VAUBAN_ARGON2_ITERATIONS` | `[auth].argon2_iterations` | 2 |
| `VAUBAN_ARGON2_PARALLELISM` | `[auth].argon2_parallelism` | 1 |

#### Access Service Environment

| Variable | Source | Default |
|----------|--------|---------|
| `VAUBAN_IPC_READ` | Supervisor pipe FD | Required |
| `VAUBAN_IPC_WRITE` | Supervisor pipe FD | Required |
| `VAUBAN_WEB_IPC_READ` | Topology channel FD | Optional |
| `VAUBAN_WEB_IPC_WRITE` | Topology channel FD | Optional |
| `VAUBAN_ACCESS_MODEL_PATH` | `[access].model_path` | `config/access/model.conf` |
| `VAUBAN_ACCESS_POLICY_PATH` | `[access].policy_path` | `config/access/default_policy.csv` |
| `VAUBAN_DATABASE_URL` | `[access].database_url` | Optional |

### 11.2 TOML Configuration

```toml
# config/default.toml

[access]
model_path = "config/access/model.conf"
policy_path = "config/access/default_policy.csv"
# database_url = "postgresql://vauban_access:password@localhost/vauban_access"

[security.argon2]
memory_size_kb = 65536
iterations = 3
parallelism = 1
```

### 11.3 Environment Variable Cleanup

Both services clear all environment variables immediately after reading them, before entering the sandbox. This prevents leaked credentials if the process memory is dumped:

```rust
unsafe {
    std::env::remove_var("VAUBAN_IPC_READ");
    std::env::remove_var("VAUBAN_IPC_WRITE");
    std::env::remove_var("VAUBAN_ACCESS_MODEL_PATH");
    std::env::remove_var("VAUBAN_ACCESS_POLICY_PATH");
    std::env::remove_var("VAUBAN_DATABASE_URL");
    // ... all topology channel vars
}
```

---

## 12. Security Analysis

### 12.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Web process compromise | Password hashing isolated in `vauban-auth`; authorization logic isolated in `vauban-access` |
| Password hash exposure | Plaintext passwords use `SensitiveString` (zeroize on drop, redacted Debug) |
| Credential remnants in memory | Argon2 params and IPC FDs cleared from env immediately; `SensitiveString` zeroizes on drop |
| Authorization bypass | RBAC deny-by-default in release builds; instance-level access fail-closed on IPC error |
| Policy tampering | Casbin model/policy loaded from files before sandbox; no file access after `cap_enter()` |
| Database injection | All queries use Diesel ORM with parameterized queries |
| Privilege escalation | Services run as separate UIDs (903, 904); Capsicum prevents new resource acquisition |
| IPC spoofing | Unix pipes are process-local; no network exposure |

### 12.2 Defense in Depth

Authorization is enforced at multiple layers:

1. **Web middleware**: RBAC check via `AccessIpcClient::check_permission()` before handler execution
2. **Web handler**: Instance-level access check via `AccessIpcClient::check_access()` before session creation
3. **Proxy service**: Independent access check via direct IPC to `vauban-access` before protocol handshake
4. **Database**: Row-level constraints (UNIQUE, FK, NOT NULL) prevent invalid data

### 12.3 Fail-Closed Behavior

| Scenario | Behavior |
|----------|----------|
| `vauban-auth` unreachable | Login fails (password cannot be verified) |
| `vauban-access` unreachable (RBAC) | Release: all actions denied; Debug: all actions allowed |
| `vauban-access` unreachable (access rules) | Connection denied (fail-closed) |
| Database connection lost in `vauban-access` | `AccessResponse::Error` returned; web shows error page |
| Invalid Casbin policy file | Service fails to start; supervisor does not respawn indefinitely |

### 12.4 Audit Trail

All authorization decisions are logged via the `tracing` framework with structured fields:

```
INFO vauban_access: RBAC check subject="role:staff" object="users" action="write" allowed=true
INFO vauban_access: Access granted user_id=42 asset_group_id=1 protocol="ssh" rule_count=2
INFO vauban_access: Access denied: no matching rules user_id=99 asset_group_id=5 protocol="rdp"
```

---

## 13. Testing Strategy

### 13.1 vauban-auth Tests

| Test Category | Count | Description |
|---------------|-------|-------------|
| ServiceState | 3 | Default values, uptime tracking, Argon2 params |
| Control messages | 2 | Ping/Pong, Drain/DrainComplete |
| Auth request/response | 3 | AuthRequest, MfaVerify, unexpected messages |
| Argon2id hashing | 4 | Hash + verify, wrong password, invalid hash format, multiple requests |
| M-8/M-10 regression | 5 | No `process::exit()`, shutdown flag, main loop checks, env var cleanup |

### 13.2 vauban-access Tests

| Test Category | Count | Description |
|---------------|-------|-------------|
| Service state | 1 | Default values |
| Control messages | 3 | Ping/Pong, Drain, Control via handle_message |
| RBAC fallback | 1 | Debug build allows without enforcer |
| Casbin enforcer | 8 | Load success/failure, superuser wildcard, staff permissions, user restrictions, unknown role denial |
| Request ID preservation | 1 | Response echoes request_id correctly |
| Counter tracking | 1 | requests_processed incremented per check |
| Structural regression | 4 | cfg(debug_assertions) guard, Casbin integration, M-8/M-10 patterns |

### 13.3 Handler Tests (vauban-access)

Database integration tests in `vauban-access/src/handlers.rs`:

| Test Category | Count | Description |
|---------------|-------|-------------|
| Vauban group CRUD | 5 | Create, get, get not found, list, delete |
| Asset group CRUD | 2 | Create, list |
| Access rule CRUD | 2 | Create, list |
| Membership | 1 | Add, list, remove group members |
| Access evaluation | 3 | Denied (no rule), allowed, wrong protocol denied |
| Accessible groups | 1 | List accessible groups with protocol aggregation |
| Group options | 1 | Dropdown data loading |

### 13.4 Web Integration Tests

Tests in `vauban-web/tests/`:

| Test File | Scope |
|-----------|-------|
| `api/access_rules_test.rs` | REST API CRUD for access rules |
| `api/access_control_test.rs` | API-level access control enforcement |
| `web/access_rules_crud_web_test.rs` | Web form CRUD for access rules |
| `web/access_control_web_test.rs` | Web UI access control enforcement |
| `ipc/access_ipc_test.rs` | IPC client communication with vauban-access |
| `security/security_test.rs` | RBAC guard enforcement across all endpoints |

---

## 14. Architecture Decisions

### 14.1 Summary of Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Separate auth service | Dedicated `vauban-auth` | Isolate cryptographic operations from web process |
| Unified access service | `vauban-access` = RBAC + instance-level | Single source of truth for all authorization decisions |
| Casbin for RBAC | File-based policy engine | Auditable, configurable without code changes, proven engine |
| SQL for instance-level | Diesel-async + PostgreSQL | Complex queries (JOINs, time windows, array containment) |
| Async runtime in sync service | Single-threaded Tokio | Required by `diesel-async`; minimal overhead in current_thread mode |
| SensitiveString | Custom zeroizing wrapper | Prevent credential leaks in logs and memory dumps |
| Drop FK for DB separation | `ALTER TABLE assets DROP CONSTRAINT` | Enable separate PostgreSQL instances for web and access data |
| Dual fallback mode | cfg(debug_assertions) | Dev convenience vs production security |
| Priority-based rules | `priority` column | Explicit conflict resolution for overlapping access rules |
| Protocol-level granularity | `text[]` column | Single rule can grant SSH but not RDP (or vice versa) |

### 14.2 Why Not Separate RBAC and Instance-Level Services?

Combining both authorization layers in `vauban-access` was chosen over two separate services because:

1. **Single authorization authority**: All "can user X do Y?" questions go to one service, simplifying the architecture
2. **Fewer IPC pipes**: One pipe pair instead of two reduces topology complexity
3. **Shared context**: Instance-level checks may need role information (future), avoiding cross-service IPC
4. **Operational simplicity**: One service to monitor, one database to manage

### 14.3 Why Argon2id in a Separate Service?

Password hashing is isolated in `vauban-auth` rather than inline in `vauban-web` because:

1. **CPU isolation**: Argon2id is intentionally CPU/memory-intensive; isolating it prevents DoS against the web server
2. **Memory safety**: Password material (plaintext + hash) never enters the web process address space
3. **Principle of least privilege**: The web process does not need the ability to hash passwords
4. **Future expansion**: `vauban-auth` will handle SSO (OIDC/SAML), LDAP sync, and advanced MFA, which benefit from dedicated process isolation

### 14.4 Why a Tokio Runtime in a "Synchronous" Service?

`vauban-access` uses a single-threaded Tokio runtime despite being classified as a synchronous service because:

1. `diesel-async` (the async Diesel adapter) requires an async executor
2. The `current_thread` runtime has minimal overhead (no thread pool, no work stealing)
3. Casbin's `DefaultModel::from_file()` is also async (uses tokio::fs)
4. The runtime is used exclusively via `block_on()` in the synchronous main loop, maintaining the sequential request processing guarantee

---

## Appendix A: Complete Login Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant W as vauban-web
    participant A as vauban-auth
    participant AC as vauban-access
    participant V as vauban-vault
    participant DB as PostgreSQL (web)

    U->>W: POST /login (username, password)
    W->>DB: SELECT * FROM users WHERE username = ?
    Note over W: User found, has password_hash

    W->>A: AuthVerifyPassword(password_hash, password)
    Note over A: Argon2id verification
    A->>W: AuthVerifyPasswordResponse(valid: true)

    alt User has MFA enabled
        W->>U: Redirect to /login/mfa
        U->>W: POST /login/mfa (code)
        W->>V: VaultMfaVerify(encrypted_secret, code)
        V->>W: VaultMfaVerifyResponse(valid: true)
    end

    W->>AC: RbacCheck("role:user", "sessions", "create")
    AC->>W: RbacResponse(allowed: true)

    W->>DB: INSERT INTO sessions (user_id, ...)
    W->>U: 302 Redirect + Session Cookie
```

---

## Appendix B: Complete SSH Connection Authorization Flow

```mermaid
sequenceDiagram
    participant U as User Browser
    participant W as vauban-web
    participant AC as vauban-access
    participant S as vauban-supervisor
    participant P as vauban-proxy-ssh
    participant V as vauban-vault
    participant T as Target Server

    U->>W: Click "Connect SSH" on asset (asset_id, group_id)

    Note over W,AC: Instance-level access check
    W->>AC: AccessRequest::CheckAccess(user_id, group_id, "ssh")
    AC->>W: AccessChecked(allowed: true, require_mfa: false)

    Note over W,AC: RBAC feature check
    W->>AC: RbacCheck("role:user", "sessions", "create")
    AC->>W: RbacResponse(allowed: true)

    Note over W,S: TCP connection brokering
    W->>S: TcpConnectRequest(session_id, host, port, ProxySsh)
    S->>T: DNS + TCP connect
    S->>P: send_fd(connected_socket) via SCM_RIGHTS
    S->>W: TcpConnectResponse(success)

    Note over W,P: SSH session setup
    W->>P: SshSessionOpen(session_id, credentials, host_key)
    P->>V: VaultGetCredential(asset_id)
    V->>P: VaultCredentialResponse(ssh_key)
    P->>T: SSH handshake (over pre-connected socket)
    P->>W: SshSessionOpened(success)

    W->>U: Redirect to /sessions/terminal/{id}
```

---

## Appendix C: Workspace Structure (IAM-related)

```
/Users/mnemonic/Code/Vauban/
├── config/
│   └── access/
│       ├── model.conf              # Casbin RBAC model definition
│       └── default_policy.csv      # Default three-role policy
├── shared/src/
│   └── messages.rs                 # AccessRequest, AccessResponse, Auth messages
├── vauban-auth/
│   ├── Cargo.toml                  # argon2 0.5, rand 0.8
│   └── src/
│       └── main.rs                 # Auth service (password hash/verify)
├── vauban-access/
│   ├── Cargo.toml                  # casbin, diesel-async, deadpool
│   └── src/
│       ├── main.rs                 # Service entry (Casbin + message dispatch)
│       ├── lib.rs                  # Library crate exports
│       ├── handlers.rs             # 24 AccessRequest handlers
│       ├── db.rs                   # Connection pool (sandbox-compatible)
│       └── schema.rs               # Diesel schema (4 tables)
├── vauban-web/
│   ├── src/
│   │   ├── ipc/
│   │   │   ├── auth.rs             # AuthIpcClient (verify/hash)
│   │   │   └── access.rs           # AccessIpcClient (RBAC + access rules)
│   │   ├── services/
│   │   │   ├── rbac.rs             # RbacService wrapper
│   │   │   └── access.rs           # Access service (IPC or SQL fallback)
│   │   ├── handlers/
│   │   │   ├── web/access_rules.rs # Web form handlers (CSRF + RBAC)
│   │   │   └── api/access_rules.rs # REST API handlers
│   │   ├── models/
│   │   │   └── access_rule.rs      # Diesel model + API DTOs
│   │   └── templates/assets/
│   │       ├── access_list.rs      # Access rules list template
│   │       ├── access_rule_create.rs
│   │       ├── access_rule_detail.rs
│   │       └── access_rule_edit.rs
│   └── migrations/
│       ├── 20260311000000_access_rules/
│       │   └── up.sql              # CREATE TABLE access_rules
│       └── 20260312000000_drop_asset_group_fk/
│           └── up.sql              # DROP FK for DB separation
└── vauban-supervisor/src/
    └── config.rs                   # AuthConfig, AccessConfig
```

---
