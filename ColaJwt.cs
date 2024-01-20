using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Cola.Core.Models.ColaJwt;
using Cola.Core.Utils;
using Cola.CoreUtils.Constants;
using Cola.CoreUtils.Enums;
using Cola.CoreUtils.Extensions;
using Cola.CoreUtils.Helper;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Cola.ColaJwt;

public class ColaJwt : IColaJwt
{
    private readonly ColaJwtOption _colaJwtOption;

    public ColaJwt(IConfiguration configuration)
    {
        _colaJwtOption = configuration.GetSection(SystemConstant.CONSTANT_COLAJWT_SECTION).Get<ColaJwtOption>();
    }
    
    /// <summary>
    /// CreateTokenDescriptor
    /// </summary>
    /// <param name="tokenUserInfo">sysCurrentUserInfo</param>
    /// <returns></returns>
    public SecurityTokenDescriptor CreateTokenDescriptor(TokenUserInfo tokenUserInfo)
    {
        var securityKey = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_colaJwtOption.SecretKey)),
            SecurityAlgorithms.HmacSha256);
        return new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>()
            {
                { JwtRegisteredClaimNames.Jti, tokenUserInfo.CurrentUserId },
            },
            Subject = new ClaimsIdentity(new Claim[]{ new Claim(JwtRegisteredClaimNames.Sub, tokenUserInfo.CurrentLoginName) }),
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
    /// <param name="securityTokenDescriptor">securityTokenDescriptor</param>
    /// <returns></returns>
    public TokenResult CreateToken(SecurityTokenDescriptor securityTokenDescriptor)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var securityToken = jwtTokenHandler.CreateToken(securityTokenDescriptor);
        var token = jwtTokenHandler.WriteToken(securityToken);
        var refreshToken = new RefreshToken() 
        {
            JwtId = securityToken.Id,
            TokenId = securityTokenDescriptor.Claims["jti"].ToString()!,
            CreationTime = securityTokenDescriptor.IssuedAt!.Value.DateTimeToUnixTime(),
            ExpiryTime = securityTokenDescriptor.Expires!.Value.DateTimeToUnixTime(),
            Token = Convert.ToBase64String(Encoding.UTF8.GetBytes(GenerationCodeHelper.GenerationCode(32,true,true,false)))
        };
        return new TokenResult()
        {
            Token = new AccessToken()
            {
                Token = token,
                ExpiresIn = UnixTimeHelper.FromDateTime(securityTokenDescriptor.Expires!.Value),
            },
            RefreshToken = refreshToken,
        };
    }
    
    /// <summary>
    /// ValidateToken
    /// </summary>
    /// <param name="token">token</param>
    /// <param name="storedRefreshToken">storedRefreshToken</param>
    /// <returns></returns>
    /// <exception cref="ColaExceptionUtils">Validate err</exception>
    public TokenUserInfo ValidateToken(string token, RefreshToken? storedRefreshToken = null)
    {
        var secretKey = _colaJwtOption.SecretKey;
        
        var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),
                ClockSkew = TimeSpan.Zero,
                ValidateLifetime = false // 不验证过期时间！！！
            };
        
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var validateClaimsPrincipal =
                jwtTokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        
            var validatedSecurityAlgorithm = validatedToken is JwtSecurityToken jwtSecurityToken
                                             && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                                                 StringComparison.InvariantCultureIgnoreCase);
        
            var claimsPrincipal = validatedSecurityAlgorithm ? validateClaimsPrincipal : null;
            if (claimsPrincipal == null)
            {
                // 无效的token...
                throw new ColaExceptionUtils(EnumException.InvalidToken);
            }
            var expiryDateUnix =
                long.Parse(claimsPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expiryDateTimeUtc = UnixTimeHelper.GetDateTime(expiryDateUnix.ToString());
            if (expiryDateTimeUtc < DateTime.Now)
            {
                // token过期...
                throw new ColaExceptionUtils(EnumException.TokenExpire);
            }

            var jti = claimsPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            if (storedRefreshToken != null)
            {

                if (storedRefreshToken == null)
                {
                    // 无效的refresh_token...
                    throw new ColaExceptionUtils(EnumException.InvalidRefreshToken);
                }

                if (storedRefreshToken.ExpiryTime.LongToDateTime() < DateTime.Now)
                {
                    // refresh_token已过期...
                    throw new ColaExceptionUtils(EnumException.RefreshTokenExpire);
                }

                if (storedRefreshToken.Invalidated)
                {
                    // refresh_token已失效...
                    throw new ColaExceptionUtils(EnumException.RefreshTokenNullified);
                }

                if (storedRefreshToken.Used)
                {
                    // refresh_token已使用...
                    throw new ColaExceptionUtils(EnumException.RefreshTokenUsed);
                }

                if (storedRefreshToken.JwtId != jti)
                {
                    // token 与 refresh_token不一致...
                    throw new ColaExceptionUtils(EnumException.RefreshTokenValidateJwtIdFail);
                }
            }

            return new TokenUserInfo()
            {
                CurrentUserId = jti,
                CurrentLoginName = claimsPrincipal.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Sub).Value,
            };
    }
    
    /// <summary>
    /// RefreshToken
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <returns></returns>
    public TokenResult RefreshToken(RefreshToken refreshToken)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();                                      
        var secretKey = _colaJwtOption.SecretKey;
        var securityKey = new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)), SecurityAlgorithms.HmacSha256);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            }),
            IssuedAt = DateTime.Now,
            NotBefore = DateTime.Now,
            Expires = DateTime.Now.AddMinutes(_colaJwtOption.AccessExpiration),
            SigningCredentials = securityKey
        };
        var securityToken = jwtTokenHandler.CreateToken(tokenDescriptor);
        var token = jwtTokenHandler.WriteToken(securityToken);
        var refreshTokenId = refreshToken.TokenId;
        refreshToken = new RefreshToken()
        {
            JwtId = securityToken.Id,
            TokenId = refreshTokenId,
            CreationTime = DateTime.Now.DateTimeToUnixTime(),
            ExpiryTime = DateTime.Now.AddMonths(_colaJwtOption.RefreshExpiration).DateTimeToUnixTime(),
            Token = Convert.ToBase64String(Encoding.UTF8.GetBytes(GenerationCodeHelper.GenerationCode(32,true,true,false)))
        };
        return new TokenResult()
        {
            Token = new AccessToken()
            {
                Token = token,
                ExpiresIn = _colaJwtOption.AccessExpiration * 60
            },
            RefreshToken = refreshToken,
        };
    }
}