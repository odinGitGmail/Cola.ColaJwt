### ColaJwt

[![Version](https://flat.badgen.net/nuget/v/Cola.ColaJwt?label=version)](https://github.com/odinGitGmail/Cola.ColaJwt) [![download](https://flat.badgen.net/nuget/dt/Cola.ColaJwt)](https://www.nuget.org/packages/Cola.ColaJwt) [![commit](https://flat.badgen.net/github/last-commit/odinGitGmail/Cola.ColaJwt)](https://flat.badgen.net/github/last-commit/odinGitGmail/Cola.ColaJwt) [![Blog](https://flat.badgen.net/static/blog/odinsam.com)](https://odinsam.com)

> author: odinsam

```json 配置信息
{
  "ColaJwt": {
    "SecretKey": "fFPdfMfCeysgZrHPeWWPTGrRphbvrunkGuktVkEmacazAlzFphWcGEaoHXBycxmDrWDtqomxmLfFabYTZQKocbRqNFzuSzIURBIsxruzqvzRRYhuMaxmNfviApzDGOZy@uK&&OEb",
    "IssUser": "odinsam.com",
    "Audience": "odinsam",
    "AccessExpiration": 30,
    "RefreshExpiration": 30
  }
}
```

```csharp inject
// 默认使用自定义的 ApiResponseForAuthenticationHandler scheme 重写了 Authenticate、Challenge、Forbid
builder.Services.AddColaJwt(config);
// or
builder.Services.AddColaJwt<ApiResponseForAuthenticationHandler>(config);


app.UseRouting();
// 注意位置和顺序
app.UseAuthentication();
app.UseAuthorization();
```

```csharp
// login get token
/// <summary>
/// login
/// </summary>
/// <returns></returns>
[HttpGet("/api/[Controller]/login")]
[AllowAnonymous]
public TokenResult Login()
{
    return _colaJwt.CreateToken(_colaJwt.CreateTokenDescriptor(new TokenUserInfo()
    {
        CurrentUserId = "123123",
        CurrentLoginName = "odinSam",
        CurrentUserName = "djj"
    }));
}
```

```csharp 
/// <summary>
/// Version1 需要token访问
/// </summary>
/// <returns></returns>
[HttpGet("/api/[Controller]/values1")]
[Authorize]
public string Version()
{
    string str = "abc123abc456abc";
    str = str.Replace("a", string.Empty);
    return $"1.0 {str}";
}
```
