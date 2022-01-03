using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Dto;
using SampleProject.Core.Settings;
using SampleProject.Infrastructure.Authentication;
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
        private readonly JwtBuilder _jwtBuilder;

        public JwtAuthenticationController(ILogger<JwtAuthenticationController> logger,
            JwtBuilder jwtBuilder)
        {
            _logger = logger;
            _jwtBuilder = jwtBuilder;
        }

        [HttpGet]
        [Route("")]
        public JwtResponseDto ObterTokenJWT()
        {
            _logger.LogInformation("Gerando token JWT");

            var jwtBuilder = _jwtBuilder.AddClaim(ClaimTypes.Sid, "VALOR_SID");

            var tokenString = jwtBuilder.BuildToken();

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
