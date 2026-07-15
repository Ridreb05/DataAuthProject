namespace DataAuthSimulator.Models;

// Raw shape of a row in the Users table. PasswordHash is a bcrypt hash
// (never a plaintext password, never anything reversible) and never
// leaves this type - it's read here, checked in AuthService, and never
// serialized back to any client.
public class AppUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTime? LockedUntil { get; set; }
}
