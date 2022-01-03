using Microsoft.IdentityModel.Tokens;
using SampleProject.Core.Settings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SampleProject.Infrastructure.Authentication
{
    public class JwtBuilder
    {
        private readonly JwtHeader _jwtHeader;
        private readonly JwtSettings _jwtSettings;
        private readonly IList<Claim> _jwtClaims;
        private readonly DateTime _jwtDate;
        public JwtBuilder(JwtSettings jwtSettings) {
            _jwtSettings = jwtSettings;
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            var credentials = new SigningCredentials(key: new SymmetricSecurityKey(key), algorithm: SecurityAlgorithms.HmacSha256Signature);
            _jwtHeader = new JwtHeader(credentials);
            _jwtClaims = new List<Claim>();
            _jwtDate = DateTime.UtcNow;
        }

        public JwtBuilder AddClaim(string key, string value) {
            return AddClaim(new Claim(key, value));
        }

        public JwtBuilder AddClaim(Claim claim)
        {
            _jwtClaims.Add(claim);
            return this;
        }

        public long TokenExpirationInUnixTime => new DateTimeOffset(_jwtDate.AddMinutes(30)).ToUnixTimeMilliseconds();

        public string BuildToken()
        {
            var jwt = new JwtSecurityToken(
                _jwtHeader,
                new JwtPayload(
                    audience : _jwtSettings.Audience,
                    issuer : _jwtSettings.Issuer,
                    notBefore: _jwtDate,
                    expires: _jwtDate.AddMinutes(30),
                    claims : _jwtClaims
                )
            );

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public TokenValidationParameters BuildTokenValidationParameters()
        {
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
            return new TokenValidationParameters {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = true,
                RequireAudience = true,
                RequireExpirationTime = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidAudience = "",
                ValidIssuer = "",
                ValidIssuers = new List<string>(),
                ValidAudiences = new List<string>(),
            };
        }
    }
}
