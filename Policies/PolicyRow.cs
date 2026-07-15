namespace DataAuthSimulator.Policies;

// Exact shape of one row in the RoleAccessPolicies table. Dapper maps
// straight into this - it's intentionally close to the table schema
// rather than the in-memory RoleAccessPolicyConfig shape, since the
// database stores Columns as a flat comma-separated string rather than
// a JSON array.
internal class PolicyRow
{
    public string Role { get; set; } = string.Empty;
    public string? RowFilterColumn { get; set; }
    public string? RowFilterOperator { get; set; }
    public string? RowFilterValue { get; set; }
    public string Columns { get; set; } = string.Empty;
}
