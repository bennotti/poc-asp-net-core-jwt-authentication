using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Settings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace SampleProject.Infrastructure.Authentication.Handle
{
    public class SampleProjectAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly JwtSettings _jwtSettings;

        public SampleProjectAuthenticationHandler(
            JwtSettings jwtSettings,
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            _jwtSettings = jwtSettings;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var endpoint = Context.GetEndpoint();
            if (endpoint == null || endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null) return AuthenticateResult.NoResult();

            if (endpoint?.Metadata?.GetMetadata<IAuthorizeData>() == null) return AuthenticateResult.NoResult();

            try {
                //var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                //var authorization = authHeader.Parameter?.Split(" ").Last();
                //if (string.IsNullOrEmpty(authorization)) {
                //    return AuthenticateResult.Fail("Invalid Authorization");
                //}
                //var tokenHandler = new JwtSecurityTokenHandler();
                //var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
                //tokenHandler.ValidateToken(authorization, new TokenValidationParameters {
                //    ValidateIssuerSigningKey = true,
                //    IssuerSigningKey = new SymmetricSecurityKey(key),
                //    ValidateIssuer = false,
                //    ValidateAudience = false,
                //    // definir clockskew para zero para que os tokens expirem exatamente no tempo de expiração do token(em vez de 5 minutos depois)
                //    ClockSkew = TimeSpan.Zero,
                //    SaveSigninToken = true
                //}, out SecurityToken validatedToken);

                //var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                //var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                //var username = credentials[0];
                //var password = credentials[1];
                //if (username != "teste" || password != "teste")
                //{
                //    return AuthenticateResult.Fail("Invalid Username or Password");
                //}
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            var claims = new[] {
                new Claim(ClaimTypes.Name, "username"),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            await Task.CompletedTask;
            return AuthenticateResult.Success(ticket);
        }
    }
}
