using System.Security.Claims;
using Cola.Core.Models.ColaJwt;
using Microsoft.IdentityModel.Tokens;

namespace Cola.ColaJwt;

public interface IColaJwt
{
    /// <summary>
    /// GenerateToken
    /// </summary>
    /// <param name="loginUserId">loginUserId</param>
    /// <returns>token</returns>
    string GenerateToken(string loginUserId);

    /// <summary>
    /// GetPrincipalFromToken
    /// </summary>
    /// <param name="token">token</param>
    /// <returns>success true</returns>
    ClaimsPrincipal GetPrincipalFromToken(string token);

    /// <summary>
    /// RefreshToken
    /// </summary>
    /// <param name="token">token</param>
    /// <returns></returns>
    string RefreshToken(string token);
}