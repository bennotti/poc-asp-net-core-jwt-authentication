using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Settings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SampleProject.Infrastructure.Authorization.Handle
{
    public class JwtHandler : AuthorizationHandler<JwtRequirement>
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly JwtSettings _tokenConfig;

        public JwtHandler(IHttpContextAccessor httpContextAccessor, JwtSettings tokenConfig)
        {
            _tokenConfig = tokenConfig;
            _httpContextAccessor = httpContextAccessor;
        }
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtRequirement requirement)
        {
            if (_httpContextAccessor == null)
            {
                context.Fail();
                return;
            }
            var authorization = _httpContextAccessor.HttpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (string.IsNullOrEmpty(authorization))
            {
                context.Fail();
                return;
            }

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_tokenConfig.Secret);
                tokenHandler.ValidateToken(authorization, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // definir clockskew para zero para que os tokens expirem exatamente no tempo de expiração do token(em vez de 5 minutos depois)
                    ClockSkew = TimeSpan.Zero,
                    SaveSigninToken = true
                }, out SecurityToken validatedToken);

                context.Succeed(requirement);
            }
            catch
            {
                // não faça nada se a validação jwt falhar
                // conta não está anexada ao contexto, então a solicitação não terá acesso a rotas seguras

                context.Fail();
            }

            

            await Task.CompletedTask;
        }
    }
}
