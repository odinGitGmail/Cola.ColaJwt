### ColaJwt

[![Version](https://flat.badgen.net/nuget/v/Cola.ColaJwt?label=version)](https://github.com/odinGitGmail/Cola.ColaJwt) [![download](https://flat.badgen.net/nuget/dt/Cola.ColaJwt)](https://www.nuget.org/packages/Cola.ColaJwt) [![commit](https://flat.badgen.net/github/last-commit/odinGitGmail/Cola.ColaJwt)](https://flat.badgen.net/github/last-commit/odinGitGmail/Cola.ColaJwt) [![Blog](https://flat.badgen.net/static/blog/odinsam.com)](https://odinsam.com)

> author: odinsam

```json 配置信息
{
  "ColaJwt": {
    "Secret": "123456123456123456123456",
    "IsUser": "odinsam.com",
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
// create token
[HttpGet("GetToken")]
public ApiResult  GetToken()
{
    var jwtConfig = _configuration.GetSection("ColaJwt");
    var tokenResult = TokenHelper.CreateToken(
        "odinsam",
        jwtConfig.GetValue<string>("Secret"),
        new ClaimsIdentity(new[]
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new Claim(JwtRegisteredClaimNames.Sub, "odinsam")
        }),
        jwtConfig.GetValue<int>("AccessExpiration"),
        jwtConfig.GetValue<int>("RefreshExpiration"));
    dicToken.TryAdd(tokenResult.Refresh.Token, tokenResult.Refresh);
    return new ApiResult
    {
        Code = 0,
        Data = tokenResult
    };
}
```

```csharp 
//validation token
[Authorize]
    [HttpGet("GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
    }
```

```csharp
//验证token
[HttpGet("ValidateToken")]
public ApiResult ValidateToken(string token,string refreshToken)
{
    try
    {
        var jwtConfig = _configuration.GetSection("ColaJwt");
        var secretKey = jwtConfig.GetValue<string>("Secret");
        dicToken.TryGetValue(refreshToken,out var storedRefreshToken);
        var validateResult = TokenHelper.ValidateToken(secretKey, token, storedRefreshToken);
        storedRefreshToken.Used = validateResult;
        return new ApiResult()
        {
            Message = "validate success, refreshToken is used"
        };
    }
    catch
    {
        return null;
    }
}
```

