namespace DataAuthSimulator.Models;

// Raw shape of a row in the RefreshTokens table. Only a SHA-256 hash of
// the actual refresh token is ever stored - a database leak alone
// cannot be used to forge a session, the same way a password hash
// alone can't be used to log in.
public class RefreshTokenRecord
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string TokenHash { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}
