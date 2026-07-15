using System.Reflection;
using DataAuthSimulator.Models;
using DataAuthSimulator.Policies;
using DataAuthSimulator.Repositories;

namespace DataAuthSimulator.Services;

public interface ISensitiveRecordService
{
    Task<object> GetFilteredDataAsync(string role);
}

// Column filtering happens here. Rows already came pre-filtered from the
// Repository, so this layer's only job is picking, per row, the exact
// set of fields configured for that role (policy.Columns) - there's no
// per-role DTO class to keep in sync with the Repository's rules
// anymore. Adding or removing a visible column for a role is a config
// edit in appsettings.json, not a new class or a code change here.
public class SensitiveRecordService : ISensitiveRecordService
{
    private readonly ISensitiveRecordRepository _repository;
    private readonly AccessPolicyProvider _policyProvider;

    // Reflection lookup is done once per property name, not per row -
    // cheap enough for a POC, and keeps the projection logic generic
    // instead of hand-writing a mapping per role.
    private static readonly Dictionary<string, PropertyInfo> RecordProperties =
        typeof(SensitiveRecord).GetProperties().ToDictionary(p => p.Name);

    public SensitiveRecordService(ISensitiveRecordRepository repository, AccessPolicyProvider policyProvider)
    {
        _repository = repository;
        _policyProvider = policyProvider;
    }

    public async Task<object> GetFilteredDataAsync(string role)
    {
        if (!_policyProvider.Policies.TryGetValue(role, out var policy))
        {
            throw new UnauthorizedAccessException($"Role '{role}' is not recognized by this system.");
        }

        var records = await _repository.GetRecordsForRoleAsync(role);

        return records.Select(record =>
        {
            // Guest users are heavily masked; Support drops Salary and
            // PerformanceRating entirely - all of that is just "which
            // column names are in policy.Columns" now, not separate
            // hand-written mapping code per role.
            var projected = new Dictionary<string, object?>();
            foreach (var column in policy.Columns)
            {
                projected[column] = RecordProperties[column].GetValue(record);
            }
            return projected;
        }).ToList();
    }
}
