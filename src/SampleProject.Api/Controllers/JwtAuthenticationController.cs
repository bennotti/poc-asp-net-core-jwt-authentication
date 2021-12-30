using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Dto;
using SampleProject.Core.Settings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SampleProject.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JwtAuthenticationController : ControllerBase
    {
        
        private readonly ILogger<JwtAuthenticationController> _logger;
        private readonly JwtSettings _jwtSettings;

        public JwtAuthenticationController(ILogger<JwtAuthenticationController> logger,
            JwtSettings jwtSettings)
        {
            _logger = logger;
            _jwtSettings = jwtSettings;
        }

        [HttpGet]
        [Route("")]
        public JwtResponseDto ObterTokenJWT()
        {
            _logger.LogInformation("Gerando token JWT");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var dataExpiracao = DateTime.UtcNow.AddMinutes(30);

            var claims = new List<Claim> {
                new Claim(ClaimTypes.Sid, "VALOR_SID")
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = dataExpiracao,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return new JwtResponseDto
            {
                Schema = "Bearer",
                AccessToken = tokenString,
            };
        }

        [HttpPost]
        [Route("validate")]
        [Authorize]
        public JwtValidateResponseDto PostValidate()
        {
            _logger.LogInformation("Token JWT validado");
            return new JwtValidateResponseDto
            {
                Msg = "Token JWT validado!"
            };
        }
    }
}
