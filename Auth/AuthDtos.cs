namespace DataAuthSimulator.Auth;

public record LoginRequest(string Username, string Password);

public record RefreshRequest(string RefreshToken);

// What the client actually receives - never the password hash, never
// anything about other users, never an indication of *why* a login
// failed beyond a generic message (see AuthService for why).
public record LoginResponse(string AccessToken, DateTime AccessTokenExpiresAt, string RefreshToken, string Role);
