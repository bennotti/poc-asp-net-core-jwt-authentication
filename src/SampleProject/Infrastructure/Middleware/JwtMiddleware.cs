using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Settings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SampleProject.Infrastructure.Middleware
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly JwtSettings _tokenConfig;

        public JwtMiddleware(RequestDelegate next, JwtSettings tokenConfig)
        {
            _tokenConfig = tokenConfig;
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (token != null)
                await validateTokenDb(context, jwtTokensRepository, token);

            await _next(context);
        }

        private async Task validateTokenDb(HttpContext context, IJwtTokensRepository jwtTokensRepository, string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_tokenConfig.Secret);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // definir clockskew para zero para que os tokens expirem exatamente no tempo de expiração do token(em vez de 5 minutos depois)
                    ClockSkew = TimeSpan.Zero,
                    SaveSigninToken = true
                }, out SecurityToken validatedToken);

                //validar token no banco de dados
                var jwtTokenBd = await jwtTokensRepository.ObterPorToken(token);

                if (jwtTokenBd != null && jwtTokenBd.DataExpiracao >= DateTime.UtcNow && !jwtTokenBd.Revogada)
                {
                    // validar vencimento
                    // validar rebogado
                    // anexar conta ao contexto na validação jwt bem-sucedida
                    context.Items["IsValidToken"] = true;
                }
            }
            catch
            {
                // não faça nada se a validação jwt falhar
                // conta não está anexada ao contexto, então a solicitação não terá acesso a rotas seguras
            }
        }
    }
}
