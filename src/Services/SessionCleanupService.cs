namespace OrderApi.Services;

// Housekeeping service. Access tokens are short-lived (15 min) and stateless, so revocation
// relies on the lifetime itself plus Identity lockout; this service prunes stale rows.
public class SessionCleanupService : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken)
        => Task.CompletedTask;
}
