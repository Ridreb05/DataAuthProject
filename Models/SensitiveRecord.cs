namespace DataAuthSimulator.Models;

// Raw shape of a row as it comes back from SQL Server. This is the
// full, unfiltered record - it should never be sent to a client directly.
// The Service layer is responsible for narrowing this down per role.
public class SensitiveRecord
{
    public int Id { get; set; }
    public string EmployeeName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
    public decimal Salary { get; set; }
    public string PerformanceRating { get; set; } = string.Empty;
    public int ActiveTickets { get; set; }
    public string PublicNotes { get; set; } = string.Empty;
}
