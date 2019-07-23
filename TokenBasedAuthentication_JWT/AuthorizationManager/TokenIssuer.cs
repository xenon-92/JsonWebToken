using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Configuration;

namespace TokenBasedAuthentication_JWT.AuthorizationManager
{
    public class TokenIssuer
    {
        private string Secret = WebConfigurationManager.AppSettings["Secret"];
        public string GenerateJWT(string username, string ip, int expireTime = 5)
        {
            try
            {
                var symmetricKey = Convert.FromBase64String(Secret);
                var TokenHandler = new JwtSecurityTokenHandler();
                DateTime now = DateTime.UtcNow;
                var TokenDescriptor = new SecurityTokenDescriptor();
                string refreshToken = CreateRefreshToken();
                List<Claim> claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.Name,username),
                    new Claim("client",ip),
                    new Claim("refresh_token",refreshToken)
                };
                ClaimsIdentity id = new ClaimsIdentity(claims);
                TokenDescriptor.Subject = new ClaimsIdentity(id);
                TokenDescriptor.IssuedAt = now;
                TokenDescriptor.Issuer = WebConfigurationManager.AppSettings["issr"];
                TokenDescriptor.Expires = now.AddMinutes(Convert.ToInt32(expireTime));
                TokenDescriptor.SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature);
                var securityToken = TokenHandler.CreateToken(TokenDescriptor);
                var token = TokenHandler.WriteToken(securityToken);
                return token;
            }
            catch (Exception ex)
            {

                throw ex;
            }
        }
        public static string CreateRefreshToken()
        {
            //https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings
            Guid g = Guid.NewGuid();
            return g.ToString();
            
        }
    }
}