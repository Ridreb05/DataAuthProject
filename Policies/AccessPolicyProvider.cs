using System.Data;
using Dapper;
using DataAuthSimulator.Models;
using Microsoft.Data.SqlClient;

namespace DataAuthSimulator.Policies;

// The row/column rules per role live in the RoleAccessPolicies table,
// not in C# and not in a config file. This class loads them into an
// in-memory snapshot once at startup (Program.cs calls LoadAsync before
// the app starts serving requests) and can reload that snapshot on
// demand - see the POST /admin/reload-policies endpoint - so a rule
// change made directly in the database takes effect without restarting
// the app.
//
// The Repository and Service never talk to this table directly; they
// only ever read the cached Policies snapshot here, so a reload can
// never leave them looking at a half-updated set of rules.
public class AccessPolicyProvider
{
    // Column names and operators are still checked against fixed
    // whitelists before ever touching a SQL string. The table is the
    // source of the *rules*, but it is never trusted as a source of raw
    // SQL - a bad or malicious row can only fail validation, never be
    // interpolated into a query.
    private static readonly HashSet<string> AllowedColumns =
        typeof(SensitiveRecord).GetProperties().Select(p => p.Name).ToHashSet();

    // The actual column->SQL-operator mapping now lives inside
    // dbo.sp_GetSensitiveRecordsForRole; this app-side list exists only
    // to validate a role's configured operator before it's ever sent
    // to the database, so a typo fails loudly here rather than as an
    // opaque SQL error from inside the procedure.
    private static readonly HashSet<string> AllowedOperators =
        new() { "Equals", "NotEquals", "GreaterThan", "LessThan" };

    private readonly string _connectionString;
    private readonly ILogger<AccessPolicyProvider> _logger;

    // volatile so a reload's atomic reference swap is immediately
    // visible to concurrent requests on other threads, without needing
    // a lock on every read.
    private volatile IReadOnlyDictionary<string, RoleAccessPolicyConfig> _policies =
        new Dictionary<string, RoleAccessPolicyConfig>();

    public IReadOnlyDictionary<string, RoleAccessPolicyConfig> Policies => _policies;

    public AccessPolicyProvider(IConfiguration configuration, ILogger<AccessPolicyProvider> logger)
    {
        _connectionString = configuration.GetConnectionString("SqlServer")
            ?? throw new InvalidOperationException("SqlServer connection string is not configured.");
        _logger = logger;
    }

    // Reads the entire RoleAccessPolicies table, validates every row,
    // and atomically swaps in the new snapshot. Safe to call again at
    // any time after startup - readers always see either the old
    // snapshot or the fully-loaded new one, never a partial state.
    public async Task LoadAsync()
    {
        var previousRoleCount = _policies.Count;

        try
        {
            using var connection = new SqlConnection(_connectionString);
            var rows = await connection.QueryAsync<PolicyRow>(
                "dbo.sp_GetAccessPolicies",
                commandType: CommandType.StoredProcedure);

            var loaded = new Dictionary<string, RoleAccessPolicyConfig>();

            foreach (var row in rows)
            {
                var config = new RoleAccessPolicyConfig
                {
                    Role = row.Role,
                    RowFilter = string.IsNullOrEmpty(row.RowFilterColumn)
                        ? null
                        : new RowFilterConfig
                        {
                            Column = row.RowFilterColumn!,
                            Operator = row.RowFilterOperator!,
                            Value = row.RowFilterValue!
                        },
                    Columns = row.Columns
                        .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                        .ToList()
                };

                Validate(config);
                loaded[config.Role] = config;
            }

            if (loaded.Count == 0)
            {
                throw new InvalidOperationException(
                    "RoleAccessPolicies has no rows - authorization rules must be defined before the app can start.");
            }

            _policies = loaded;

            // Deliberately logs role names and column lists (what changed),
            // never row-level employee data - this is an audit trail for
            // policy changes, not a data access log.
            _logger.LogInformation(
                "Access policies loaded: {RoleCount} role(s) ({Roles}). Previous cache had {PreviousCount}.",
                loaded.Count, string.Join(", ", loaded.Keys), previousRoleCount);
        }
        catch (Exception ex)
        {
            // The old snapshot in _policies is untouched on failure - a
            // bad reload never leaves the app running with a half-applied
            // or empty rule set. Only startup's first call can actually
            // crash the app; a later reload just keeps serving the last
            // known-good policies and surfaces this in the logs.
            _logger.LogError(ex, "Failed to load access policies from RoleAccessPolicies. Keeping previous snapshot ({PreviousCount} role(s)).", previousRoleCount);
            throw;
        }
    }

    private static void Validate(RoleAccessPolicyConfig policy)
    {
        if (string.IsNullOrWhiteSpace(policy.Role))
        {
            throw new InvalidOperationException("A RoleAccessPolicies row is missing a Role name.");
        }

        if (policy.Columns.Count == 0)
        {
            throw new InvalidOperationException($"Role '{policy.Role}' has no Columns configured - it would see nothing.");
        }

        foreach (var column in policy.Columns)
        {
            if (!AllowedColumns.Contains(column))
            {
                throw new InvalidOperationException(
                    $"Unknown column '{column}' configured for role '{policy.Role}'. Valid columns: {string.Join(", ", AllowedColumns)}.");
            }
        }

        if (policy.RowFilter is not null)
        {
            if (!AllowedColumns.Contains(policy.RowFilter.Column))
            {
                throw new InvalidOperationException(
                    $"Unknown row filter column '{policy.RowFilter.Column}' for role '{policy.Role}'.");
            }

            if (!AllowedOperators.Contains(policy.RowFilter.Operator))
            {
                throw new InvalidOperationException(
                    $"Unknown row filter operator '{policy.RowFilter.Operator}' for role '{policy.Role}'. Valid operators: {string.Join(", ", AllowedOperators)}.");
            }
        }
    }
}
