using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DataAuthSimulator.Models;
using Microsoft.IdentityModel.Tokens;

namespace DataAuthSimulator.Auth;

// Issues the two tokens a successful login produces:
//
//   - a short-lived JWT access token (the same kind DataHub already
//     validates - nothing about the Hub's [Authorize]/role-claim logic
//     changes, this class just becomes the thing that mints tokens
//     instead of jwt.io)
//   - a long-lived opaque refresh token, used only against /auth/refresh
//     to get a new access token without asking for a password again
//
// Short access token lifetimes limit how long a stolen token is useful
// for; the refresh token (itself never sent to DataHub, never a JWT)
// is what lets a client stay signed in without repeatedly prompting
// for credentials.
public class JwtTokenGenerator
{
    private readonly string _secret;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenMinutes;

    public JwtTokenGenerator(IConfiguration configuration)
    {
        _secret = configuration["Jwt:Secret"]
            ?? throw new InvalidOperationException("Jwt:Secret is not configured.");
        _issuer = configuration["Jwt:Issuer"]
            ?? throw new InvalidOperationException("Jwt:Issuer is not configured.");
        _audience = configuration["Jwt:Audience"]
            ?? throw new InvalidOperationException("Jwt:Audience is not configured.");
        _accessTokenMinutes = int.TryParse(configuration["Jwt:AccessTokenMinutes"], out var minutes)
            ? minutes
            : 15;
    }

    public (string Token, DateTime ExpiresAt) GenerateAccessToken(AppUser user)
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(_accessTokenMinutes);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim("role", user.Role),
            new Claim("username", user.Username),
            // A unique jti per token is standard practice - it's what
            // would let a future revocation list target one specific
            // access token rather than only being able to block by user.
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: credentials);

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
    }

    // 256 bits of randomness from a CSPRNG, base64url-encoded - not a
    // JWT, just an opaque bearer secret. It's never decoded or
    // inspected, only hashed and compared against what's stored.
    public static string GenerateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    // Refresh tokens are stored as this hash, never in their original
    // form - the same principle as password hashing: a database leak
    // shouldn't hand over usable credentials.
    public static string HashToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }
}
