using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Cola.Core.ColaEx;
using Cola.Core.Models.ColaJwt;
using Cola.CoreUtils.Constants;
using Cola.CoreUtils.Enums;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Cola.ColaJwt;

public class ColaJwt : IColaJwt
{
    private readonly ColaJwtOption _colaJwtOption;
    private readonly IColaException _colaException;
    public ColaJwt(
        IConfiguration configuration, 
        IColaException colaException)
    {
        _colaJwtOption = configuration.GetSection(SystemConstant.CONSTANT_COLAJWT_SECTION).Get<ColaJwtOption>();
        _colaException = colaException;
    }
    
    /// <summary>
    /// CreateTokenDescriptor
    /// </summary>
    /// <param name="loginUserId">loginUserId</param>
    /// <returns></returns>
    private SecurityTokenDescriptor CreateTokenDescriptor(string loginUserId)
    {
        _colaException.ThrowStringIsNullOrEmpty(loginUserId, EnumException.ParamNotNull);
        var securityKey = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_colaJwtOption.SecretKey)),
            SecurityAlgorithms.HmacSha256);
        return new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>()
            {
                { JwtRegisteredClaimNames.Jti, loginUserId },
            },
            Subject = new ClaimsIdentity(new Claim[]{ new Claim(JwtRegisteredClaimNames.Sub, loginUserId) }),
            IssuedAt = DateTime.Now,
            NotBefore = DateTime.Now,
            Expires = DateTime.Now.AddMinutes(_colaJwtOption.AccessExpiration),
            SigningCredentials = securityKey,
            Issuer = "Issuer",
        };
    }
    
    /// <summary>
    /// CreateToken
    /// </summary>
    /// <param name="loginUserId">loginUserId</param>
    /// <returns></returns>
    public string GenerateToken(string loginUserId)
    {
        var securityTokenDescriptor = CreateTokenDescriptor(loginUserId);
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var securityToken = jwtTokenHandler.CreateToken(securityTokenDescriptor);
        var token = jwtTokenHandler.WriteToken(securityToken);
        return token;
    }

    public ClaimsPrincipal GetPrincipalFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var securityKey = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_colaJwtOption.SecretKey)),
                SecurityAlgorithms.HmacSha256);
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey.Key,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true // You may want to change this depending on your requirements
            }, out var validatedToken);

            if (!(validatedToken is JwtSecurityToken jwtToken) ||
                !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
        catch
        {
            return null;
        }
    }

    // /// <summary>
    // /// ValidateToken
    // /// </summary>
    // /// <param name="token">token</param>
    // /// <returns></returns>
    // /// <exception cref="ColaExceptionUtils">Validate err</exception>
    // public TokenUserInfo ValidateToken(string token)
    // {
    //     var secretKey = _colaJwtOption.SecretKey;
    //     var tokenValidationParameters = new TokenValidationParameters
    //         {
    //             ValidateIssuer = false,
    //             ValidateAudience = false,
    //             ValidateIssuerSigningKey = true,
    //             IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),
    //             ClockSkew = TimeSpan.Zero,
    //             ValidateLifetime = false // 不验证过期时间！！！
    //         };
    //         var jwtTokenHandler = new JwtSecurityTokenHandler();
    //         var validateClaimsPrincipal =
    //             jwtTokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
    //     
    //         var validatedSecurityAlgorithm = validatedToken is JwtSecurityToken jwtSecurityToken
    //                                          && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
    //                                              StringComparison.InvariantCultureIgnoreCase);
    //         var claimsPrincipal = validatedSecurityAlgorithm ? validateClaimsPrincipal : null;
    //         if (claimsPrincipal == null)
    //         {
    //             // 无效的token...
    //             throw new ColaExceptionUtils(EnumException.InvalidToken);
    //         }
    //         var expiryDateUnix =
    //             long.Parse(claimsPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
    //         var expiryDateTimeUtc = UnixTimeHelper.GetDateTime(expiryDateUnix.ToString());
    //         if (expiryDateTimeUtc < DateTime.Now)
    //         {
    //             // token过期...
    //             throw new ColaExceptionUtils(EnumException.TokenExpire);
    //         }
    //
    //         var jti = claimsPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
    //         
    // }
    
    /// <summary>
    /// RefreshToken
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public string RefreshToken(string token)
    {
        var securityKey = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_colaJwtOption.SecretKey)),
            SecurityAlgorithms.HmacSha256);
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey.Key,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false
        }, out var validatedToken);

        var jwtToken = validatedToken as JwtSecurityToken;
        if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }
        var jit = principal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
        return GenerateToken(jit);
    }
}