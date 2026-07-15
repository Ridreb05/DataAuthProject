# Data Authorization Simulator

A minimal but industry-practice-following .NET 8 SignalR service that
demonstrates row- and column-level data authorization, enforced
entirely by the `role` claim in a client's JWT, with the actual
authorization rules stored in the database rather than hardcoded in C#.

The project includes a real login backend: username/password
authentication against bcrypt-hashed credentials, short-lived JWT
access tokens, rotating refresh tokens with reuse detection, account
lockout after repeated failed attempts, and rate limiting on the auth
endpoints. Nothing here is a hand-crafted or pre-signed test token —
`wwwroot/demo.html` signs you in for real, the same way any client
would.

## Contents

- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Authorization matrix](#authorization-matrix-default-configuration)
- [Changing the rules (no restart needed)](#changing-the-rules-no-restart-needed)
- [Setup](#setup)
  1. [Database](#1-database-setup)
  2. [Configuration](#2-configuration)
  3. [Run the app](#3-run-the-app)
- [Try it in the browser (demo page)](#try-it-in-the-browser-demo-page)
- [Auth endpoints](#auth-endpoints)
- [Operational endpoints](#operational-endpoints)
- [Notes on scope](#notes-on-scope)

## How It Works

A client signs in, receives a JWT for its role, connects over
WebSocket with that token, invokes one method, and gets back only the
data its role is allowed to see:

0. **`POST /auth/login`** *(Auth)* — the client sends a username and
   password. `AuthService` looks the user up, verifies the password
   against its bcrypt hash, checks it isn't locked out, and — on
   success — issues a short-lived JWT access token (with a `role`
   claim) and a rotating refresh token. A wrong password, unknown user,
   or locked account all return the same generic error, so this
   endpoint never reveals which part was wrong.
1. **`DataHub`** *(Hubs)* — the client invokes `RequestDataStream()`.
   The Hub reads the `role` claim off the connection's validated token.
2. **`SensitiveRecordService`** *(Services)* — receives the role and
   asks `AccessPolicyProvider` for that role's rules.
3. **`AccessPolicyProvider`** *(Policies)* — returns the row filter and
   allowed columns for that role, from an in-memory cache loaded from
   the `RoleAccessPolicies` table at startup — not hardcoded anywhere.
4. **`SensitiveRecordRepository`** *(Repositories)* — calls the
   `dbo.sp_GetSensitiveRecordsForRole` stored procedure with the role's
   row filter as parameters. **Row filtering happens here** — only
   allowed rows ever leave the database.
5. **`SensitiveRecordService`** *(Services, again)* — takes those rows
   and keeps only the columns the role's policy allows. **Column
   filtering happens here** — dropped columns are never serialized.
6. **`DataHub`** sends the filtered result back to that one caller:
   `Clients.Caller.SendAsync("ReceiveDataStream", data)`.

Steps 1–6 repeat for every reconnect. The access token from step 0 is
short-lived (15 minutes by default); `demo.html` calls
**`POST /auth/refresh`** in the background to get a new one before it
expires, without asking for the password again — see
[Auth endpoints](#auth-endpoints).

Two things are deliberate here:

**Row filtering and column filtering are separated by layer.** The
Repository is the only place that talks to SQL Server for the actual
employee data, and it only ever fetches rows the caller is allowed to
see — nothing downstream of it can accidentally leak a row it never
should have received. The Service is the only place that decides which
*columns* of an already-authorized row are safe to serialize.

**Neither rule is written in C#, or even in a file.** The row filter and
column list for every role live in the `RoleAccessPolicies` table.
`AccessPolicyProvider` loads that table into an in-memory cache once at
startup, and can reload it on demand — see
[Changing the Rules](#changing-the-rules-no-restart-needed) — so a rule
change takes effect without restarting the app.

## Project Structure

```
DataAuthSimulator/
  Program.cs                     JWT/config validation, DI wiring, middleware, policy load at startup
  appsettings.json                Connection string + JWT secret/issuer/audience
  .gitignore                      Excludes build output and local secret overrides
  DataAuthSimulator.csproj
  Models/
    SensitiveRecord.cs            Raw, unfiltered shape of one SensitiveRecords row
    AppUser.cs                    Raw shape of one Users table row
    RefreshTokenRecord.cs         Raw shape of one RefreshTokens table row
  Policies/
    RoleAccessPolicyConfig.cs     In-memory shape of one role's rule
    PolicyRow.cs                  Exact shape of one RoleAccessPolicies table row
    AccessPolicyProvider.cs       Loads, caches, validates, and reloads the rules
  Auth/
    AuthDtos.cs                   Request/response shapes for /auth/* endpoints
    IPasswordHasher.cs            bcrypt hashing/verification
    JwtTokenGenerator.cs          Mints access tokens, generates/hashes refresh tokens
    AuthService.cs                Login, refresh (with rotation + reuse detection), logout, lockout
  Repositories/
    SensitiveRecordRepository.cs  Only file that talks to SQL Server for employee data; row filtering
    UserRepository.cs             Users + RefreshTokens data access, via stored procedures
  Services/
    SensitiveRecordService.cs     Projects rows down to allowed columns per role
  Hubs/
    DataHub.cs                    SignalR entry point; [Authorize], reads role claim, logs connection events
  Health/
    SqlServerHealthCheck.cs       Backs GET /health with a real SQL Server round-trip
  wwwroot/
    demo.html                     Real login screen + dashboard — signs in against /auth/login
```

| Layer | Responsibility | Knows about SQL? | Knows about column rules? |
|---|---|---|---|
| `Hubs` | Auth gate, reads the role claim, calls the Service | No | No |
| `Services` | Column filtering | No | Yes |
| `Repositories` | Row filtering | Yes | No |
| `Policies` | Single source of truth for both rules, cached from the DB | Yes (reads `RoleAccessPolicies` only) | No — just holds the data |

## Authorization Matrix (default configuration)

| Role | Row Filter | Columns Visible |
|---|---|---|
| **Admin** | none | all 7 columns |
| **Manager** | `Department <> 'HR'` | all except `PerformanceRating` |
| **HR** | `Department <> 'Admin'` | all except `ActiveTickets` |
| **Support** | `ActiveTickets > 0` | `Id`, `EmployeeName`, `Department`, `ActiveTickets`, `PublicNotes` |
| **Guest** | none | `Id`, `EmployeeName`, `PublicNotes` only |

This table isn't code — it's the default seed data in `RoleAccessPolicies`.

## Changing the Rules (No Restart Needed)

Each role is one row in `RoleAccessPolicies`:

| Column | Meaning |
|---|---|
| `Role` | Must match the `role` claim in a client's JWT |
| `RowFilterColumn` / `RowFilterOperator` / `RowFilterValue` | All `NULL` for no row restriction, or a single comparison (see operators below) |
| `Columns` | Comma-separated list of allowed field names |

**To give Managers back `PerformanceRating`:**

```sql
UPDATE RoleAccessPolicies
SET Columns = 'Id,EmployeeName,Department,Salary,PerformanceRating,ActiveTickets,PublicNotes'
WHERE Role = 'Manager';
```

**To add a sixth role**, insert a new row with a `Role` value matching
the `role` claim you'll put in that role's JWT.

Either way, the change takes effect the moment someone calls the reload
endpoint — no rebuild, no restart:

```
POST /admin/reload-policies      (Admin role required)
```

Concretely:

```bash
curl -X POST http://localhost:<port>/admin/reload-policies \
  -H "Authorization: Bearer <an Admin-role JWT>"
```

This re-reads the entire `RoleAccessPolicies` table and atomically swaps
the in-memory cache — every request after this point uses the new
rules; nothing before it did.

Supported `RowFilterOperator` values: `Equals`, `NotEquals`,
`GreaterThan`, `LessThan`. Every column name, operator, and role name is
validated against a fixed whitelist on every load, in
`AccessPolicyProvider` — a typo or an unknown column fails that load
immediately with a clear error, rather than silently doing the wrong
thing or opening any injection risk.

## Setup

### 1. Database Setup

Run this against a SQL Server instance. It creates both tables this
project uses — the employee data and the authorization rules — plus
seed rows for each.

```sql
CREATE DATABASE DataAuthSimulatorDb;
GO

USE DataAuthSimulatorDb;
GO

CREATE TABLE SensitiveRecords (
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    EmployeeName      NVARCHAR(100)   NOT NULL,
    Department        NVARCHAR(50)    NOT NULL,
    Salary            DECIMAL(10, 2)  NOT NULL,
    PerformanceRating NVARCHAR(20)    NOT NULL,
    ActiveTickets     INT             NOT NULL,
    PublicNotes       NVARCHAR(200)   NULL
);
GO

INSERT INTO SensitiveRecords
    (EmployeeName, Department, Salary, PerformanceRating, ActiveTickets, PublicNotes)
VALUES
    ('Alice Chen',      'Engineering', 145000.00, 'Exceeds Expectations', 2, 'On-call this week'),
    ('Brian Osei',      'Engineering',  98000.00, 'Meets Expectations',   0, 'Out of office Fri'),
    ('Carla Mendes',    'HR',          110000.00, 'Exceeds Expectations', 0, 'HR office hours 2-4pm'),
    ('David Kim',       'Admin',       180000.00, 'Meets Expectations',   0, 'Executive assistant'),
    ('Elena Petrova',   'Support',      72000.00, 'Needs Improvement',    5, 'Handling escalations'),
    ('Farid Haidari',   'Support',      75000.00, 'Meets Expectations',   0, 'No open tickets'),
    ('Grace Liu',       'Engineering', 132000.00, 'Exceeds Expectations', 1, 'Leading Q3 migration'),
    ('Hassan Ali',      'HR',          105000.00, 'Meets Expectations',   3, 'Reviewing benefits renewal');
GO

CREATE TABLE RoleAccessPolicies (
    Id                INT IDENTITY(1,1) PRIMARY KEY,
    Role              NVARCHAR(50)    NOT NULL UNIQUE,
    RowFilterColumn   NVARCHAR(50)    NULL,
    RowFilterOperator NVARCHAR(20)    NULL,
    RowFilterValue    NVARCHAR(100)   NULL,
    Columns           NVARCHAR(500)   NOT NULL,
    ModifiedAt        DATETIME2       NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

INSERT INTO RoleAccessPolicies
    (Role, RowFilterColumn, RowFilterOperator, RowFilterValue, Columns)
VALUES
    ('Admin',   NULL,           NULL,          NULL, 'Id,EmployeeName,Department,Salary,PerformanceRating,ActiveTickets,PublicNotes'),
    ('Manager', 'Department',   'NotEquals',   'HR', 'Id,EmployeeName,Department,Salary,ActiveTickets,PublicNotes'),
    ('HR',      'Department',   'NotEquals',   'Admin', 'Id,EmployeeName,Department,Salary,PerformanceRating,PublicNotes'),
    ('Support', 'ActiveTickets','GreaterThan', '0', 'Id,EmployeeName,Department,ActiveTickets,PublicNotes'),
    ('Guest',   NULL,           NULL,          NULL, 'Id,EmployeeName,PublicNotes');
GO

-- Both queries the app issues run as stored procedures, not inline SQL.
-- The row filter's column name is turned into a safe identifier with
-- QUOTENAME, and the value is always bound through sp_executesql as a
-- real parameter - never string-concatenated. Access to the underlying
-- tables can be locked down to EXEC-only on these two procedures rather
-- than granting the app's SQL login direct SELECT on the tables.

CREATE OR ALTER PROCEDURE dbo.sp_GetSensitiveRecordsForRole
    @RowFilterColumn   NVARCHAR(50)  = NULL,
    @RowFilterOperator NVARCHAR(20)  = NULL,
    @RowFilterValue    NVARCHAR(100) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF @RowFilterColumn IS NULL
    BEGIN
        SELECT * FROM SensitiveRecords;
        RETURN;
    END

    DECLARE @OperatorSymbol NVARCHAR(2) = CASE @RowFilterOperator
        WHEN 'Equals'      THEN '='
        WHEN 'NotEquals'   THEN '<>'
        WHEN 'GreaterThan' THEN '>'
        WHEN 'LessThan'    THEN '<'
        ELSE NULL
    END;

    IF @OperatorSymbol IS NULL
        THROW 50000, 'Unknown row filter operator.', 1;

    DECLARE @Sql NVARCHAR(MAX) =
        N'SELECT * FROM SensitiveRecords WHERE ' + QUOTENAME(@RowFilterColumn) + N' ' + @OperatorSymbol + N' @Value';

    EXEC sp_executesql @Sql, N'@Value NVARCHAR(100)', @Value = @RowFilterValue;
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_GetAccessPolicies
AS
BEGIN
    SET NOCOUNT ON;
    SELECT Role, RowFilterColumn, RowFilterOperator, RowFilterValue, Columns
    FROM RoleAccessPolicies;
END
GO

-- ============================================================
-- Login backend: Users + RefreshTokens
-- ============================================================
-- PasswordHash is a bcrypt hash (via BCrypt.Net-Next in the app) -
-- never a plaintext or reversibly-encrypted password. FailedLoginAttempts
-- and LockedUntil back the account-lockout behavior in AuthService.

CREATE TABLE Users (
    Id                  INT IDENTITY(1,1) PRIMARY KEY,
    Username            NVARCHAR(100)  NOT NULL UNIQUE,
    PasswordHash        NVARCHAR(200)  NOT NULL,
    Role                NVARCHAR(50)   NOT NULL,
    IsActive            BIT            NOT NULL DEFAULT 1,
    FailedLoginAttempts INT            NOT NULL DEFAULT 0,
    LockedUntil         DATETIME2      NULL,
    CreatedAt           DATETIME2      NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

-- RefreshTokens never stores the actual token - only a SHA-256 hash of
-- it (see JwtTokenGenerator.HashToken) - the same principle as storing
-- a password hash instead of the password. ReplacedByHash chains a
-- rotated-out token to the one that replaced it, which is what lets
-- AuthService detect reuse of an already-rotated token as a signal of
-- possible theft.
CREATE TABLE RefreshTokens (
    Id             INT IDENTITY(1,1) PRIMARY KEY,
    UserId         INT NOT NULL FOREIGN KEY REFERENCES Users(Id),
    TokenHash      NVARCHAR(200) NOT NULL UNIQUE,
    ExpiresAt      DATETIME2 NOT NULL,
    CreatedAt      DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    RevokedAt      DATETIME2 NULL,
    ReplacedByHash NVARCHAR(200) NULL
);
GO

-- Demo users, one per role, all with the password Password123!
-- These hashes were generated with bcrypt (work factor 11) - the app
-- verifies them with the same algorithm regardless of which tool
-- produced the hash. Change or remove these before using this schema
-- for anything beyond a local demo.
INSERT INTO Users (Username, PasswordHash, Role) VALUES
    ('admin.demo',   '$2b$11$XBtA8HnzOzTLhTgbGil3/eTq5uhWDP0lchoLwW6B72fvq2/wX7Zfu', 'Admin'),
    ('manager.demo', '$2b$11$Ye7/2Qu5Idm5VKzUf5WRRu9SJkN5N9f6d0cE/g6plMsA8LTUZ8qMi', 'Manager'),
    ('hr.demo',      '$2b$11$2ZTgQ1WNQHlok9nzMHsrw.1AfRGmRNEV55GygoyB9arLblCMEEI6m', 'HR'),
    ('support.demo', '$2b$11$fGu0fYudEuQfy1utI7FP0OXuIEh5OyuuYzlACuodc3JgPNWAwMNNa', 'Support'),
    ('guest.demo',   '$2b$11$xEy5f/C.qeQohWfHtkxnMOtutve9Jt0ajnSzQWjMQ3twNkfJQrcyi', 'Guest');
GO

CREATE OR ALTER PROCEDURE dbo.sp_GetUserByUsername
    @Username NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT Id, Username, PasswordHash, Role, IsActive, FailedLoginAttempts, LockedUntil
    FROM Users
    WHERE Username = @Username;
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_GetUserById
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;
    SELECT Id, Username, PasswordHash, Role, IsActive, FailedLoginAttempts, LockedUntil
    FROM Users
    WHERE Id = @UserId;
END
GO

-- Locks the account for 15 minutes after the 5th consecutive failed
-- attempt, then resets the counter - matching AuthService's constants
-- (MaxFailedAttempts, LockoutDuration). Kept in sync deliberately: the
-- app decides *when* an attempt counts as failed, the database just
-- tracks the count and enforces the lock.
CREATE OR ALTER PROCEDURE dbo.sp_RecordFailedLogin
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE Users
    SET FailedLoginAttempts = FailedLoginAttempts + 1,
        LockedUntil = CASE
            WHEN FailedLoginAttempts + 1 >= 5 THEN DATEADD(MINUTE, 15, SYSUTCDATETIME())
            ELSE LockedUntil
        END
    WHERE Id = @UserId;
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_RecordSuccessfulLogin
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE Users
    SET FailedLoginAttempts = 0,
        LockedUntil = NULL
    WHERE Id = @UserId;
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_InsertRefreshToken
    @UserId    INT,
    @TokenHash NVARCHAR(200),
    @ExpiresAt DATETIME2
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO RefreshTokens (UserId, TokenHash, ExpiresAt)
    VALUES (@UserId, @TokenHash, @ExpiresAt);
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_GetRefreshToken
    @TokenHash NVARCHAR(200)
AS
BEGIN
    SET NOCOUNT ON;
    SELECT Id, UserId, TokenHash, ExpiresAt, RevokedAt
    FROM RefreshTokens
    WHERE TokenHash = @TokenHash;
END
GO

CREATE OR ALTER PROCEDURE dbo.sp_RevokeRefreshToken
    @TokenHash      NVARCHAR(200),
    @ReplacedByHash NVARCHAR(200) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE RefreshTokens
    SET RevokedAt = SYSUTCDATETIME(),
        ReplacedByHash = @ReplacedByHash
    WHERE TokenHash = @TokenHash;
END
GO

-- Used when AuthService detects a revoked refresh token being reused -
-- a signal the token may have been stolen. Nukes every active session
-- for the user rather than trusting the one request in front of it.
CREATE OR ALTER PROCEDURE dbo.sp_RevokeAllUserRefreshTokens
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE RefreshTokens
    SET RevokedAt = SYSUTCDATETIME()
    WHERE UserId = @UserId AND RevokedAt IS NULL;
END
GO
```

### 2. Configuration

Edit `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "SqlServer": "Server=localhost\\SQLEXPRESS;Database=DataAuthSimulatorDb;Trusted_Connection=True;TrustServerCertificate=True;"
  },
  "Jwt": {
    "Secret": "this-is-a-poc-signing-secret-change-me-32bytes-min",
    "Issuer": "DataAuthSimulator",
    "Audience": "DataAuthSimulatorClient",
    "AccessTokenMinutes": 15
  }
}
```

- `ConnectionStrings:SqlServer` — point at your SQL Server instance and
  the database created above. This same connection string is used for
  `SensitiveRecords`, `RoleAccessPolicies`, `Users`, and `RefreshTokens`.
  The example above uses Windows Authentication against a local named
  instance (`SQLEXPRESS`); swap in `User Id=...;Password=...;` if you're
  using SQL auth instead, or a full server name for a remote/cloud
  instance.
- `Jwt:Secret` — the symmetric HMAC key this app now both **signs and
  validates** tokens with (login issues tokens; the hub and other
  endpoints validate them). Must be at least 32 bytes for HS256 —
  startup fails immediately if it's shorter. Change this before using
  the project beyond a local demo.
- `Jwt:Issuer` / `Jwt:Audience` — embedded in every token this app
  issues, and required to match on validation.
- `Jwt:AccessTokenMinutes` — how long an access token is valid for
  before a client needs to use its refresh token to get a new one
  (default 15).

The authorization rules themselves are **not** in this file — see
`RoleAccessPolicies`, described above.

### 3. Run the App

```bash
dotnet restore
dotnet run
```

On startup, the app loads and validates the entire
`RoleAccessPolicies` table before it accepts any requests — if that
table is empty, missing, or has a bad row (unknown column, unknown
operator), the app fails immediately with a clear error instead of
serving requests with broken rules. Watch the console for the
`Now listening on: http://localhost:XXXX` line — the port can change
between runs. Then open `http://localhost:<port>/demo.html` and sign in
with one of the demo accounts below — no manual token generation is
needed.

## Try It in the Browser (Demo Page)

This is the intended way to try the project — open one URL, sign in for
real, see the result. No other client or tool is needed.

```
http://localhost:<port>/demo.html
```

`wwwroot/demo.html` is a two-screen app: a **login screen** and a
**dashboard**. The login screen is a real login — it calls
`POST /auth/login` with a username and password, which are checked
against the `Users` table server-side. There is nothing to decode or
paste; the browser never sees a token until the server issues one.

**Login screen:**

- A standard username/password form (with a show/hide toggle on the
  password field) posts to `/auth/login`. A wrong password, unknown
  username, or locked-out account all show the same generic error
  message — the login endpoint never reveals which one it was.
- Five "quick demo login" buttons fill in and submit one of the seeded
  demo accounts below, so you don't have to type credentials to try
  each role.
- On success, the page stores the returned access token, its expiry,
  and the refresh token, then opens the SignalR connection.

Demo accounts (seeded by the SQL script above), all using the password
`Password123!`:

| Username | Role |
|---|---|
| `admin.demo` | Admin |
| `manager.demo` | Manager |
| `hr.demo` | HR |
| `support.demo` | Support |
| `guest.demo` | Guest |

**Dashboard:**

- A connection status pill (connecting / connected / reconnecting /
  disconnected) reflects SignalR's real connection state, including
  automatic reconnect attempts if the connection drops.
- KPI cards show row count, column count, and the signed-in role at a
  glance.
- The table is sortable (click a column header) and has a client-side
  search box — both operate only on rows/columns the server already
  sent; neither can reveal anything the server withheld.
- **Admins** get an extra "Reload access policies" button that calls
  `POST /admin/reload-policies` with the current access token and
  immediately re-requests data, so a rule change is visible in the same
  screen without a manual `curl` call.
- The page proactively calls `POST /auth/refresh` in the background
  (roughly a minute before the access token expires) to keep the
  session alive without asking for the password again — including
  right after a page reload, since the refresh token is kept in
  `sessionStorage`. If the refresh token itself has expired or been
  revoked, the page signs itself out and returns to the login screen.
- "Sign out" calls `POST /auth/logout` to revoke the current refresh
  token server-side, then clears the local session and returns to the
  login screen. Closing the tab does *not* revoke the refresh token —
  it remains valid until it expires or is explicitly revoked, matching
  how most real apps let you stay signed in across tab closes.

For a `Support` account, for example, the table renders only rows with
`ActiveTickets > 0`, and only these columns:

```json
{ "Id": 1, "EmployeeName": "Alice Chen", "Department": "Engineering", "ActiveTickets": 2, "PublicNotes": "On-call this week" }
```

`Salary` and `PerformanceRating` are absent entirely — never serialized,
not just hidden. An unrecognized or missing role claim on the token
results in a `DataStreamError` banner shown on the dashboard instead of
data.

**To see a live rule change:** sign in as `manager.demo` on the demo
page (no `PerformanceRating` column), run the `UPDATE` from
[Changing the Rules](#changing-the-rules-no-restart-needed) in another
window, click "Reload access policies" while signed in as
`admin.demo`, then sign in as `manager.demo` again — the column now
appears, with the app never restarted.

## Auth Endpoints

| Endpoint | Auth | Rate limited | Purpose |
|---|---|---|---|
| `POST /auth/login` | none | Yes (5/min per IP) | Verifies username + password against the `Users` table (bcrypt), checks account lockout, and returns an access token + refresh token on success. Generic error on any failure. |
| `POST /auth/refresh` | none (requires a valid refresh token in the body) | Yes (5/min per IP) | Exchanges a still-valid, unrevoked refresh token for a new access token and a new refresh token. The presented refresh token is revoked and chained to the new one (rotation) — reusing an already-rotated token revokes *every* active refresh token for that user, as a defensive response to possible theft. |
| `POST /auth/logout` | none (requires a refresh token in the body) | No | Revokes the given refresh token so it can no longer be exchanged. |

Request/response bodies:

```jsonc
// POST /auth/login
{ "username": "admin.demo", "password": "Password123!" }

// 200 response (also returned by /auth/refresh)
{
  "accessToken": "eyJ...",
  "accessTokenExpiresAt": "2026-07-14T12:15:00Z",
  "refreshToken": "base64url-random-string",
  "role": "Admin"
}

// POST /auth/refresh and /auth/logout
{ "refreshToken": "base64url-random-string" }
```

Account lockout: 5 consecutive failed login attempts locks the account
for 15 minutes; a successful login resets the counter. This is tracked
in the `Users` table (`FailedLoginAttempts`, `LockedUntil`), not in
memory, so it survives an app restart.

## Operational Endpoints

Two plain HTTP endpoints exist alongside the SignalR hub and the auth
endpoints above:

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Round-trips a `SELECT 1` to SQL Server. Returns `200 Healthy` or `503 Unhealthy` — wire this into a container orchestrator's liveness/readiness probe or a load balancer health check. |
| `POST /admin/reload-policies` | JWT, `Admin` role | Re-reads `RoleAccessPolicies` and atomically swaps the in-memory cache. See [Changing the Rules](#changing-the-rules-no-restart-needed). |

Every SignalR connection event (connect, disconnect, denied requests,
and successful data requests — role and connection ID only, never row
contents) and every policy load/reload is logged through the standard
`ILogger` pipeline, visible in the console by default and configurable
via the `Logging` section of `appsettings.json`. Unhandled exceptions
anywhere in the app are caught by a global handler that logs the full
exception server-side and returns a generic `500` `ProblemDetails`
response to the client — no stack traces or internal details are ever
exposed over the wire.

## Notes on Scope

This is a proof of concept, not a production system. Rather than one
vague disclaimer, here's a specific checklist of what's actually
covered versus what's still a deliberate gap.

### Already in place

- Real login: passwords are hashed with bcrypt (never stored or logged
  in plaintext), short-lived JWT access tokens, rotating refresh tokens
  with reuse detection, account lockout after 5 failed attempts, and
  fixed-window rate limiting (5 requests/min per IP) on `/auth/login`
  and `/auth/refresh`.
- Generic, non-enumerable auth errors — an unknown username, wrong
  password, and locked account all return the same message, so a
  client (or attacker) can't tell which one occurred.
- Row and column authorization rules live in the database, not in code
  or a config file, and reload without a restart (`RoleAccessPolicies`,
  `AccessPolicyProvider`).
- Startup fails fast and loudly on bad configuration — missing JWT
  secret/issuer/audience, a secret too short for HS256, a missing or
  empty `RoleAccessPolicies` table, or an unknown column/operator in any
  row.
- Both queries the app issues run as stored procedures
  (`dbo.sp_GetSensitiveRecordsForRole`, `dbo.sp_GetAccessPolicies`), not
  inline SQL from the application — the query logic lives in the
  database, and a SQL login for this app could be scoped to `EXEC`-only
  on these two procedures instead of direct table access.
- Row filter values are always passed as real SQL parameters, and
  column names are turned into safe identifiers with `QUOTENAME` inside
  the procedure; column names and operators are also checked against a
  fixed whitelist in the app before ever reaching the database — never
  string-concatenated from untrusted input at any layer.
- Structured logging (`ILogger`) on every connection, disconnection,
  denied request, successful data request (role + connection ID only,
  never row contents), and every policy load/reload.
- A global exception handler returns a generic error to the client and
  logs the real exception server-side — no stack traces or internal
  details are ever exposed over the wire.
- `GET /health` gives an orchestrator or load balancer a real signal
  (an actual SQL Server round-trip, not just "the process is up").
- `.gitignore` excludes build output and any local override
  (`appsettings.Development.json`) so a real deployment's secrets never
  get committed alongside this repo's placeholder demo secret.

### Still deliberately out of scope

- **No external identity provider.** Login is self-hosted against the
  `Users` table rather than delegating to Entra ID, Auth0, Cognito, or
  similar — reasonable for a POC or an internal tool, but a real
  production system with SSO, MFA, or federated identity requirements
  would typically sit behind one of those instead of rolling its own
  `Users` table.
- **No password reset / account provisioning flow.** Users are seeded
  directly via SQL; there's no "forgot password," email verification,
  or self-service signup.
- **No MFA.** Login is single-factor (password only).
- **Manual policy reload, not automatic.** `/admin/reload-policies` must
  be called explicitly after a database change. A production system
  might poll on an interval, use a change-notification mechanism (SQL
  Server Service Broker, a message queue), or accept a small staleness
  window from a periodic refresh instead.
- **No data-access audit trail.** Logs record *that* a role received
  data and *when*, not the specific rows/columns returned per request —
  a compliance-grade audit trail is a further step beyond this.
- **Rate limiting is IP-based and in-memory only.** `/auth/login` and
  `/auth/refresh` are throttled per-IP within a single instance; a
  multi-instance deployment behind a load balancer would need a
  distributed rate limiter (e.g. backed by Redis) for the limit to hold
  across instances.
- **Single table of data, single hub.** A system with many entities
  would likely generalize this pattern (e.g. a `Table` column on
  `RoleAccessPolicies`) rather than repeating it per entity.
- **No automated tests.** The validation and filtering logic in
  `AccessPolicyProvider`, the Repository, and the Service are all small
  and isolated enough to unit test in a real fork of this project — no
  test project is included here to keep the POC to its core concept.
