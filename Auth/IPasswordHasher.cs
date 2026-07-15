namespace DataAuthSimulator.Auth;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hash);
}

// bcrypt (via BCrypt.Net-Next) rather than a hand-rolled PBKDF2/SHA
// scheme - it's the standard choice for password storage because the
// work factor is tunable as hardware gets faster, and the salt is
// embedded in the hash string itself so there's nothing extra to store
// or lose track of.
public class BCryptPasswordHasher : IPasswordHasher
{
    // 11 rounds is a reasonable balance for a login endpoint - enough
    // to be expensive against offline cracking, not so much that a
    // legitimate login becomes slow. Production systems typically
    // re-evaluate this every couple of years as hardware improves.
    private const int WorkFactor = 11;

    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, WorkFactor);

    public bool Verify(string password, string hash) => BCrypt.Net.BCrypt.Verify(password, hash);
}
