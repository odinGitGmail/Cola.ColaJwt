using Cola.Core.Models.ColaJwt;
using Microsoft.IdentityModel.Tokens;

namespace Cola.ColaJwt;

public interface IColaJwt
{
    SecurityTokenDescriptor CreateTokenDescriptor(TokenUserInfo tokenUserInfo);

    TokenResult CreateToken(SecurityTokenDescriptor securityTokenDescriptor);

    TokenUserInfo ValidateToken(string token, RefreshToken? storedRefreshToken = null);

    TokenResult RefreshToken(RefreshToken refreshToken);
}