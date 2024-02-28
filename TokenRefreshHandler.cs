using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Cola.ColaJwt;

public class TokenRefreshHandler : AuthorizationHandler<RefreshTokenRequirement>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IColaJwt _colaJwt;

    public TokenRefreshHandler(
        IHttpContextAccessor httpContextAccessor,
        IColaJwt colaJwt)
    {
        _httpContextAccessor = httpContextAccessor;
        _colaJwt = colaJwt;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        RefreshTokenRequirement requirement)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        var authorizationHeader = httpContext!.Request.Headers["Authorization"].ToString();

        if (string.IsNullOrEmpty(authorizationHeader))
        {
            context.Fail();
            return;
        }

        var token = authorizationHeader.Replace("Bearer ", "");
        var principal = _colaJwt.GetPrincipalFromToken(token);

        // Check if token is about to expire
        var expirationDate = principal.FindFirst(ClaimTypes.Expiration)?.Value;
        if (!string.IsNullOrEmpty(expirationDate))
        {
            var expiresAt = DateTime.Parse(expirationDate);
            var secondsUntilExpiration = expiresAt.Subtract(DateTime.UtcNow).TotalSeconds;
            
            // If token expires within specified threshold (e.g., 5 minutes), refresh token
            if (secondsUntilExpiration <= requirement.RefreshThresholdSeconds)
            {
                var refreshedToken = _colaJwt.RefreshToken(token);
                httpContext.Response.Headers["Authorization"] = "Bearer " + refreshedToken;
            }
        }

        context.Succeed(requirement);
    }
}