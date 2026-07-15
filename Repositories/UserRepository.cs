using System.Data;
using Dapper;
using DataAuthSimulator.Models;
using Microsoft.Data.SqlClient;

namespace DataAuthSimulator.Repositories;

public interface IUserRepository
{
    Task<AppUser?> GetByUsernameAsync(string username);
    Task<AppUser?> GetByIdAsync(int userId);
    Task RecordFailedLoginAsync(int userId);
    Task RecordSuccessfulLoginAsync(int userId);
    Task InsertRefreshTokenAsync(int userId, string tokenHash, DateTime expiresAt);
    Task<RefreshTokenRecord?> GetRefreshTokenAsync(string tokenHash);
    Task RevokeRefreshTokenAsync(string tokenHash, string? replacedByHash);
    Task RevokeAllUserRefreshTokensAsync(int userId);
}

// Every query here runs as a stored procedure - same pattern as
// SensitiveRecordRepository and AccessPolicyProvider. Nothing in this
// class ever concatenates a value into SQL text.
public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("SqlServer")
            ?? throw new InvalidOperationException("SqlServer connection string is not configured.");
    }

    public async Task<AppUser?> GetByUsernameAsync(string username)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<AppUser>(
            "dbo.sp_GetUserByUsername",
            new { Username = username },
            commandType: CommandType.StoredProcedure);
    }

    public async Task<AppUser?> GetByIdAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<AppUser>(
            "dbo.sp_GetUserById",
            new { UserId = userId },
            commandType: CommandType.StoredProcedure);
    }

    public async Task RecordFailedLoginAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.ExecuteAsync(
            "dbo.sp_RecordFailedLogin",
            new { UserId = userId },
            commandType: CommandType.StoredProcedure);
    }

    public async Task RecordSuccessfulLoginAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.ExecuteAsync(
            "dbo.sp_RecordSuccessfulLogin",
            new { UserId = userId },
            commandType: CommandType.StoredProcedure);
    }

    public async Task InsertRefreshTokenAsync(int userId, string tokenHash, DateTime expiresAt)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.ExecuteAsync(
            "dbo.sp_InsertRefreshToken",
            new { UserId = userId, TokenHash = tokenHash, ExpiresAt = expiresAt },
            commandType: CommandType.StoredProcedure);
    }

    public async Task<RefreshTokenRecord?> GetRefreshTokenAsync(string tokenHash)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<RefreshTokenRecord>(
            "dbo.sp_GetRefreshToken",
            new { TokenHash = tokenHash },
            commandType: CommandType.StoredProcedure);
    }

    public async Task RevokeRefreshTokenAsync(string tokenHash, string? replacedByHash)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.ExecuteAsync(
            "dbo.sp_RevokeRefreshToken",
            new { TokenHash = tokenHash, ReplacedByHash = replacedByHash },
            commandType: CommandType.StoredProcedure);
    }

    public async Task RevokeAllUserRefreshTokensAsync(int userId)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.ExecuteAsync(
            "dbo.sp_RevokeAllUserRefreshTokens",
            new { UserId = userId },
            commandType: CommandType.StoredProcedure);
    }
}
