using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Cola.Core.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Newtonsoft.Json;
using SqlSugar.Extensions;

namespace Cola.ColaJwt;

public class ColaAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IColaJwt _colaJwt;
    public ColaAuthenticationHandler(IColaJwt colaJwt, IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
        _colaJwt = colaJwt;
    }
    
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            Response.Headers.Add("WWW-Authenticate", @"Basic realm='Secure Area'");
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));
        }
        try
        {
            var token = Request.Headers["Authorization"].ObjToString().Replace("Bearer ", "");;
            var authHeader = AuthenticationHeaderValue.Parse(token);
            var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
            var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
            var sysCurrentUserInfo = _colaJwt.ValidateToken(token);
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Jti, sysCurrentUserInfo.CurrentUserId),
                new Claim(JwtRegisteredClaimNames.Sub, sysCurrentUserInfo.CurrentLoginName),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            Console.WriteLine(ticket);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch
        {
            // Base64字符串解码失败
            return Task.FromResult(AuthenticateResult.Fail("Invalid Authorization Header"));
        }
    }
    
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.ContentType = "application/json";    
        var apiResult = new ApiResult();
        apiResult.Code = 401;
        apiResult.Data = 401;
        apiResult.Message = "很抱歉，您无权访问该接口，请确保已经登录!";
        await Response.WriteAsync(JsonConvert.SerializeObject(apiResult));
    }
 
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.ContentType = "application/json";        
        var apiResult = new ApiResult();
        apiResult.Code = 403;
        apiResult.Message = "很抱歉，您的访问权限等级不够，联系管理员!!";
        await Response.WriteAsync(JsonConvert.SerializeObject(apiResult));
 
    }
}