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
    public class JwtAuthorizationHandler : AuthorizationHandler<JwtAuthorizationRequirement>
    {
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtAuthorizationRequirement requirement)
        {
            if (!context.User.Identity.IsAuthenticated)
            {
                context.Fail();
                return;
            }

            var userIdentity = context.User.Identity;

            // pode ser feito a validação do token, mesmo que valido (não expirado e assinatura correta), esta bloqueado no banco de dados ou algum outro lugar.

            context.Succeed(requirement);

            await Task.CompletedTask;
        }
    }
}
