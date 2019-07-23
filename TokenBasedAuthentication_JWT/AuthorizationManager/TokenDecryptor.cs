using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;

namespace TokenBasedAuthentication_JWT.AuthorizationManager
{
    public class TokenDecryptor
    {
        private string Secret = WebConfigurationManager.AppSettings["Secret"];
        public Task<ClaimsPrincipal> GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwt_token = tokenHandler.ReadToken(token) as JwtSecurityToken;
                if (jwt_token == null)
                {
                    return null;
                }
                byte[] symmetricKey = Convert.FromBase64String(Secret);
                var validationParameter = new TokenValidationParameters()
                {
                    ValidateLifetime = true,
                    ValidateIssuer = true,
                    ValidIssuer = "MyCustomIssuer",
                    RequireExpirationTime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
                };
                SecurityToken securityToken;
                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameter, out securityToken);
                return Task.FromResult(principal);
            }
            catch (Exception)
            {
                //write log
                return Task.FromResult<ClaimsPrincipal>(null);
            }
        }
    }
}