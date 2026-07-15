using System.Data;
using Dapper;
using DataAuthSimulator.Models;
using DataAuthSimulator.Policies;
using Microsoft.Data.SqlClient;

namespace DataAuthSimulator.Repositories;

public interface ISensitiveRecordRepository
{
    Task<IEnumerable<SensitiveRecord>> GetRecordsForRoleAsync(string role);
}

// Row filtering lives here, not in the Service layer, so we never pull
// rows into memory that the caller isn't allowed to see in the first
// place. The actual query runs as a stored procedure
// (dbo.sp_GetSensitiveRecordsForRole) rather than inline SQL - the row
// filter's column/operator/value are passed in as parameters, and the
// procedure itself builds the dynamic WHERE clause safely (QUOTENAME on
// the identifier, sp_executesql with a bound parameter for the value).
// This keeps the query logic in the database, where a DBA can review or
// tune it independently of the app, and lets access to SensitiveRecords
// be granted purely via EXEC rights on the procedure rather than direct
// table SELECT.
public class SensitiveRecordRepository : ISensitiveRecordRepository
{
    private readonly string _connectionString;
    private readonly AccessPolicyProvider _policyProvider;

    public SensitiveRecordRepository(IConfiguration configuration, AccessPolicyProvider policyProvider)
    {
        _connectionString = configuration.GetConnectionString("SqlServer")
            ?? throw new InvalidOperationException("SqlServer connection string is not configured.");
        _policyProvider = policyProvider;
    }

    public async Task<IEnumerable<SensitiveRecord>> GetRecordsForRoleAsync(string role)
    {
        if (!_policyProvider.Policies.TryGetValue(role, out var policy))
        {
            throw new UnauthorizedAccessException($"Role '{role}' is not recognized by this system.");
        }

        using var connection = new SqlConnection(_connectionString);

        // Column name and operator are both validated against a fixed
        // whitelist in AccessPolicyProvider before this ever runs. They're
        // still passed as ordinary parameters here (not concatenated) -
        // the stored procedure is what turns the column name into a safe
        // identifier via QUOTENAME, and binds the value through
        // sp_executesql rather than string-building the whole query.
        var parameters = new
        {
            RowFilterColumn = policy.RowFilter?.Column,
            RowFilterOperator = policy.RowFilter?.Operator,
            RowFilterValue = policy.RowFilter?.Value
        };

        return await connection.QueryAsync<SensitiveRecord>(
            "dbo.sp_GetSensitiveRecordsForRole",
            parameters,
            commandType: CommandType.StoredProcedure);
    }
}
