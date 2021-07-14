using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Zuilhof.JwtAuthentication
{
    public class JwtAuthenticator
    {
        private readonly string _keyJwtSecretBase64;
        private const string IdClaimType = "Id";

        public JwtAuthenticator(string keyJwtSecretBase64)
        {
            _keyJwtSecretBase64 = keyJwtSecretBase64;
        }

        public string CreateToken(int userId, int secondsValid)
        {
            var jwtSecret = GetJwtSecret();
            var handler = new JwtSecurityTokenHandler();

            var expiresAt = DateTime.UtcNow.AddSeconds(secondsValid);
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(IdClaimType, userId.ToString())
                }),
                SigningCredentials = new SigningCredentials(
                    jwtSecret,
                    SecurityAlgorithms.HmacSha256Signature),
                Expires = expiresAt
            };

            var securityToken = handler.CreateToken(tokenDescriptor);
            var token = handler.WriteToken(securityToken);

            return token;
        }
        
        public int? ValidateJwtToken(AuthenticationHeaderValue authenticationHeader)
        {
            if (authenticationHeader == null || authenticationHeader.Scheme != "Bearer")
            {
                return null;
            }
            
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(authenticationHeader.Parameter, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = GetJwtSecret(),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out var validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var claim = jwtToken.Claims.First(x => x.Type == IdClaimType);
                var accountId = int.Parse(claim.Value);

                return accountId;
            }
            catch
            {
                return null;
            }
        }

        private SymmetricSecurityKey GetJwtSecret()
        {
            var jwtSecretBytes = Convert.FromBase64String(_keyJwtSecretBase64);
            var jwtSecret = new SymmetricSecurityKey(jwtSecretBytes);

            return jwtSecret;
        }
    }
}