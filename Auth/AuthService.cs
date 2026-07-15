using DataAuthSimulator.Repositories;

namespace DataAuthSimulator.Auth;

public record AuthResult(
    bool Success,
    string? Error,
    string? AccessToken,
    DateTime? AccessTokenExpiresAt,
    string? RefreshToken,
    string? Role);

public interface IAuthService
{
    Task<AuthResult> LoginAsync(string username, string password);
    Task<AuthResult> RefreshAsync(string refreshToken);
    Task LogoutAsync(string refreshToken);
}

// Orchestrates the actual login/refresh/logout flow. Every failure path
// returns the same generic message to the caller ("Invalid username or
// password") regardless of whether the username didn't exist, the
// password was wrong, or the account is inactive - the differences are
// only visible in the server-side logs. This is deliberate: distinct
// error messages per failure reason let an attacker enumerate valid
// usernames, which a generic message doesn't.
public class AuthService : IAuthService
{
    // 5 failed attempts locks the account for 15 minutes - a standard,
    // conservative brute-force mitigation. Tunable, but these numbers
    // are a reasonable industry default (similar to what many identity
    // providers ship with out of the box).
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(7);

    private readonly IUserRepository _users;
    private readonly JwtTokenGenerator _tokenGenerator;
    private readonly IPasswordHasher _hasher;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IUserRepository users,
        JwtTokenGenerator tokenGenerator,
        IPasswordHasher hasher,
        ILogger<AuthService> logger)
    {
        _users = users;
        _tokenGenerator = tokenGenerator;
        _hasher = hasher;
        _logger = logger;
    }

    public async Task<AuthResult> LoginAsync(string username, string password)
    {
        var user = await _users.GetByUsernameAsync(username);

        if (user is null || !user.IsActive)
        {
            _logger.LogWarning("Login failed: unknown or inactive username {Username}.", username);
            return Failure();
        }

        if (user.LockedUntil is not null && user.LockedUntil > DateTime.UtcNow)
        {
            _logger.LogWarning("Login blocked: {Username} is locked out until {LockedUntil}.", username, user.LockedUntil);
            return new AuthResult(false, "This account is temporarily locked due to repeated failed logins. Try again later.", null, null, null, null);
        }

        if (!_hasher.Verify(password, user.PasswordHash))
        {
            await _users.RecordFailedLoginAsync(user.Id);
            _logger.LogWarning("Login failed: bad password for {Username}.", username);
            return Failure();
        }

        await _users.RecordSuccessfulLoginAsync(user.Id);

        var (accessToken, expiresAt) = _tokenGenerator.GenerateAccessToken(user);
        var refreshToken = JwtTokenGenerator.GenerateRefreshToken();
        await _users.InsertRefreshTokenAsync(user.Id, JwtTokenGenerator.HashToken(refreshToken), DateTime.UtcNow.Add(RefreshTokenLifetime));

        _logger.LogInformation("User {Username} (role {Role}) logged in.", username, user.Role);
        return new AuthResult(true, null, accessToken, expiresAt, refreshToken, user.Role);
    }

    public async Task<AuthResult> RefreshAsync(string refreshToken)
    {
        var hash = JwtTokenGenerator.HashToken(refreshToken);
        var record = await _users.GetRefreshTokenAsync(hash);

        if (record is null)
        {
            return new AuthResult(false, "Invalid session. Please log in again.", null, null, null, null);
        }

        if (record.RevokedAt is not null)
        {
            // A revoked refresh token being presented again is a strong
            // signal of token theft (the legitimate client already
            // rotated past it) - defensively revoke every active
            // session for this user rather than trusting this request.
            _logger.LogWarning("Revoked refresh token reused for user {UserId} - revoking all active sessions.", record.UserId);
            await _users.RevokeAllUserRefreshTokensAsync(record.UserId);
            return new AuthResult(false, "This session has been revoked for security reasons. Please log in again.", null, null, null, null);
        }

        if (record.ExpiresAt < DateTime.UtcNow)
        {
            return new AuthResult(false, "Session expired. Please log in again.", null, null, null, null);
        }

        var user = await _users.GetByIdAsync(record.UserId);
        if (user is null || !user.IsActive)
        {
            return new AuthResult(false, "Account is no longer active.", null, null, null, null);
        }

        // Rotation: every refresh issues a brand-new refresh token and
        // immediately revokes the one just used, chaining to the new
        // hash. A refresh token is single-use - if it's replayed after
        // this point, the branch above catches it.
        var (accessToken, expiresAt) = _tokenGenerator.GenerateAccessToken(user);
        var newRefreshToken = JwtTokenGenerator.GenerateRefreshToken();
        var newHash = JwtTokenGenerator.HashToken(newRefreshToken);

        await _users.InsertRefreshTokenAsync(user.Id, newHash, DateTime.UtcNow.Add(RefreshTokenLifetime));
        await _users.RevokeRefreshTokenAsync(hash, newHash);

        return new AuthResult(true, null, accessToken, expiresAt, newRefreshToken, user.Role);
    }

    public async Task LogoutAsync(string refreshToken)
    {
        var hash = JwtTokenGenerator.HashToken(refreshToken);
        await _users.RevokeRefreshTokenAsync(hash, null);
    }

    private static AuthResult Failure() =>
        new(false, "Invalid username or password.", null, null, null, null);
}
