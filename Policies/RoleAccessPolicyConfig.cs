namespace DataAuthSimulator.Policies;

// Plain data shape bound straight from the "AccessPolicies" section of
// appsettings.json - deliberately has no behavior of its own. This is
// what "the rules are data, not code" looks like: swapping which
// columns a role sees, or adding a row filter, is an edit to this
// config, not a recompile.
public class RoleAccessPolicyConfig
{
    public string Role { get; set; } = string.Empty;
    public RowFilterConfig? RowFilter { get; set; }
    public List<string> Columns { get; set; } = new();
}

// Deliberately restrictive shape - a single Column/Operator/Value
// triple, not a raw SQL fragment. Configs are written by whoever owns
// this deployment's appsettings, not by an end user, but keeping the
// shape structured (rather than accepting a free-text WHERE clause)
// means a typo or a bad edit can only ever produce an invalid filter,
// never arbitrary SQL.
public class RowFilterConfig
{
    public string Column { get; set; } = string.Empty;
    public string Operator { get; set; } = string.Empty; // Equals | NotEquals | GreaterThan | LessThan
    public string Value { get; set; } = string.Empty;
}
