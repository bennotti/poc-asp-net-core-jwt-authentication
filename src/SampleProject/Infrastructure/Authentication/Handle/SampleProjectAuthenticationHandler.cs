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

            // pode ser feito a validação do token, mesmo que valido (não expirado e assinatura correta), esta bloqueado no banco de dados ou algum outro lugar.

            var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            var authorization = authHeader.Parameter?.Split(" ").Last();
            if (string.IsNullOrEmpty(authorization))
            {
                return AuthenticateResult.Fail("Invalid Authorization");
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
