using Microsoft.AspNetCore.Authorization;

namespace Cola.ColaJwt;

public class RefreshTokenRequirement : IAuthorizationRequirement
{
    public int RefreshThresholdSeconds { get; }

    public RefreshTokenRequirement(int refreshThresholdSeconds)
    {
        RefreshThresholdSeconds = refreshThresholdSeconds;
    }
}