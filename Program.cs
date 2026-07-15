using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using DataAuthSimulator.Auth;
using DataAuthSimulator.Health;
using DataAuthSimulator.Hubs;
using DataAuthSimulator.Policies;
using DataAuthSimulator.Repositories;
using DataAuthSimulator.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR();

builder.Services.AddHealthChecks()
    .AddCheck<SqlServerHealthCheck>("sql-server");

// Login/session infrastructure. This is the actual identity provider
// for this app now - it hashes passwords (bcrypt), issues short-lived
// JWT access tokens, and issues/rotates long-lived refresh tokens.
// DataHub's [Authorize] and role-claim logic didn't change at all -
// tokens minted here are the same shape as the ones previously hand-
// crafted on jwt.io for testing.
builder.Services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddSingleton<JwtTokenGenerator>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();

// The row/column rules per role live in the RoleAccessPolicies table,
// not in C#. This is registered as a singleton because it holds an
// in-memory cache (loaded below, before the app starts serving
// requests) that every request reads from - see Policies/AccessPolicyProvider.cs.
builder.Services.AddSingleton<AccessPolicyProvider>();

builder.Services.AddScoped<ISensitiveRecordRepository, SensitiveRecordRepository>();
builder.Services.AddScoped<ISensitiveRecordService, SensitiveRecordService>();

// Throttles brute-force attempts against the login and refresh
// endpoints independently of the per-account lockout in AuthService -
// this limits by client IP regardless of which (or how many)
// usernames are being tried.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("auth", limiterOptions =>
    {
        limiterOptions.Window = TimeSpan.FromMinutes(1);
        limiterOptions.PermitLimit = 5;
        limiterOptions.QueueLimit = 0;
        limiterOptions.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
});

// All three JWT settings are required, not just the secret - a missing
// Issuer or Audience doesn't crash startup on its own (they're nullable
// strings), it just silently makes ValidIssuer/ValidAudience null,
// which rejects every token at runtime with a confusing "invalid
// token" error instead of a clear startup failure. Fail fast here
// instead.
var jwtSecret = builder.Configuration["Jwt:Secret"]
    ?? throw new InvalidOperationException("Jwt:Secret is not configured.");
var jwtIssuer = builder.Configuration["Jwt:Issuer"]
    ?? throw new InvalidOperationException("Jwt:Issuer is not configured.");
var jwtAudience = builder.Configuration["Jwt:Audience"]
    ?? throw new InvalidOperationException("Jwt:Audience is not configured.");

if (Encoding.UTF8.GetByteCount(jwtSecret) < 32)
{
    throw new InvalidOperationException(
        "Jwt:Secret must be at least 32 bytes for HS256 - the configured value is shorter than that.");
}

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            // Access tokens are already short-lived (15 minutes by
            // default - see Jwt:AccessTokenMinutes); no need for the
            // default 5-minute grace window on top of that.
            ClockSkew = TimeSpan.Zero
        };

        // SignalR sends the JWT as a query string param (access_token) on
        // the websocket handshake, not an Authorization header - the
        // browser websocket API can't set custom headers, so this bridge
        // is required for the hub's [Authorize] attribute to see the token.
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;

                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs/data"))
                {
                    context.Token = accessToken;
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Unhandled exceptions get logged with full detail server-side, but the
// client only ever sees a generic ProblemDetails response - no stack
// trace, no exception message, regardless of environment. Anything
// that needs a specific client-facing error (like the role-not-found
// case in DataHub) already handles that itself before it gets here;
// this is strictly the backstop for the unexpected.
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var exceptionHandlerFeature = context.Features.Get<IExceptionHandlerFeature>();
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(exceptionHandlerFeature?.Error, "Unhandled exception on {Path}.", context.Request.Path);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/problem+json";
        await context.Response.WriteAsJsonAsync(new
        {
            title = "An unexpected error occurred.",
            status = 500
        });
    });
});

var startupLogger = app.Services.GetRequiredService<ILogger<Program>>();

// Load the policy cache once before the app accepts any traffic - a
// bad or empty RoleAccessPolicies table fails startup immediately
// rather than surfacing as a confusing error on the first request.
using (var scope = app.Services.CreateScope())
{
    var policyProvider = scope.ServiceProvider.GetRequiredService<AccessPolicyProvider>();
    startupLogger.LogInformation("Loading access policies from RoleAccessPolicies...");
    await policyProvider.LoadAsync();
}

// Serves wwwroot/demo.html - a login screen + dashboard so this can be
// shown live without Postman or hand-rolled WebSocket frames.
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

app.MapHub<DataHub>("/hubs/data");

// /health checks a real SQL Server round-trip, not just "the process is
// running" - standard for anything meant to sit behind a load balancer
// or container orchestrator's liveness/readiness probes.
app.MapHealthChecks("/health");

app.MapGet("/api/status", () => "Data Authorization Simulator - connect to /hubs/data with a valid JWT, or open /demo.html to log in.");

// ---- Auth endpoints ----
// Real login backend: username/password against the Users table,
// bcrypt-verified, account lockout after repeated failures, and a
// short-lived access token + rotating refresh token on success.
app.MapPost("/auth/login", async (LoginRequest request, IAuthService authService) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Username and password are required." });
    }

    var result = await authService.LoginAsync(request.Username, request.Password);
    if (!result.Success)
    {
        return Results.Json(new { error = result.Error }, statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(new LoginResponse(result.AccessToken!, result.AccessTokenExpiresAt!.Value, result.RefreshToken!, result.Role!));
}).RequireRateLimiting("auth");

// Exchanges a still-valid refresh token for a new access token, without
// asking for a password again. The refresh token itself is rotated -
// the one presented here stops working the moment a new one is issued.
app.MapPost("/auth/refresh", async (RefreshRequest request, IAuthService authService) =>
{
    if (string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        return Results.BadRequest(new { error = "refreshToken is required." });
    }

    var result = await authService.RefreshAsync(request.RefreshToken);
    if (!result.Success)
    {
        return Results.Json(new { error = result.Error }, statusCode: StatusCodes.Status401Unauthorized);
    }

    return Results.Ok(new LoginResponse(result.AccessToken!, result.AccessTokenExpiresAt!.Value, result.RefreshToken!, result.Role!));
}).RequireRateLimiting("auth");

// Revokes a refresh token so it can no longer be exchanged - the
// access token already issued is short-lived enough to expire on its
// own shortly after.
app.MapPost("/auth/logout", async (RefreshRequest request, IAuthService authService) =>
{
    if (!string.IsNullOrWhiteSpace(request.RefreshToken))
    {
        await authService.LogoutAsync(request.RefreshToken);
    }

    return Results.Ok(new { loggedOut = true });
});

// Lets an Admin push a change made directly in RoleAccessPolicies (a
// new column, a tightened row filter, a brand-new role) into the
// running app's cache without a restart. Deliberately manual rather
// than polling the table on a timer, so a demo can show "before" and
// "after" on command.
app.MapPost("/admin/reload-policies", async (HttpContext context, AccessPolicyProvider policyProvider) =>
{
    var role = context.User.FindFirst(ClaimTypes.Role)?.Value
        ?? context.User.FindFirst("role")?.Value;

    if (role != "Admin")
    {
        return Results.Forbid();
    }

    await policyProvider.LoadAsync();
    return Results.Ok(new { reloaded = true, roles = policyProvider.Policies.Keys });
}).RequireAuthorization();

app.Run();
