using System.Security.Claims;
using DataAuthSimulator.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace DataAuthSimulator.Hubs;

// Requires a validated JWT to open the connection at all. Anonymous
// sockets never reach RequestDataStream.
[Authorize]
public class DataHub : Hub
{
    private readonly ISensitiveRecordService _recordService;
    private readonly ILogger<DataHub> _logger;

    public DataHub(ISensitiveRecordService recordService, ILogger<DataHub> logger)
    {
        _recordService = recordService;
        _logger = logger;
    }

    // The client invokes this after connecting; there's no payload because
    // authorization is entirely derived from the token's Role claim, not
    // from anything the client asserts about itself.
    public async Task RequestDataStream()
    {
        var role = Context.User?.FindFirst(ClaimTypes.Role)?.Value
            ?? Context.User?.FindFirst("role")?.Value;

        if (string.IsNullOrEmpty(role))
        {
            _logger.LogWarning("Connection {ConnectionId} requested data with no role claim on its token.", Context.ConnectionId);
            await Clients.Caller.SendAsync("DataStreamError", "Token has no Role claim - cannot authorize this connection.");
            return;
        }

        try
        {
            var data = await _recordService.GetFilteredDataAsync(role);

            // Logs who asked and what role decided the shape of the
            // response - never the response contents. This is a
            // structural access log (who/when/role), not the row-level
            // data audit trail called out as out of scope in the README.
            _logger.LogInformation("Connection {ConnectionId} (role: {Role}) received a filtered data stream.", Context.ConnectionId, role);
            await Clients.Caller.SendAsync("ReceiveDataStream", data);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Connection {ConnectionId} was denied: {Reason}", Context.ConnectionId, ex.Message);
            await Clients.Caller.SendAsync("DataStreamError", ex.Message);
        }
    }

    public override async Task OnConnectedAsync()
    {
        var role = Context.User?.FindFirst(ClaimTypes.Role)?.Value
            ?? Context.User?.FindFirst("role")?.Value
            ?? "unknown";

        _logger.LogInformation("Connection {ConnectionId} established (role: {Role}).", Context.ConnectionId, role);
        await Clients.Caller.SendAsync("Connected", $"Connected as role: {role}");
        await base.OnConnectedAsync();
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        if (exception is not null)
        {
            _logger.LogWarning(exception, "Connection {ConnectionId} disconnected with an error.", Context.ConnectionId);
        }
        else
        {
            _logger.LogInformation("Connection {ConnectionId} disconnected.", Context.ConnectionId);
        }

        await base.OnDisconnectedAsync(exception);
    }
}
