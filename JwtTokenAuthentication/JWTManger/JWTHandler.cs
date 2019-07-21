using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace JwtTokenAuthentication.JWTManger
{
    public class JWTHandler
    {
        private const string Secret = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMuoi6bzRqxt7BY6Q00pMjV2m82C7BgHLSudyu2ZKMaPRm3GyLNmvx0UVkoIEk7yJmzv3yeSL20n3b9Xa0YTtrECAwEAAQ==";
        //generate token
        public static string GenerateToken(string userName,int expireMinutes=20)
        {
            var symmetricKeys = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();//
            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor();
            tokenDescriptor.Subject = new System.Security.Claims.ClaimsIdentity(
                new[]
                {
                    new Claim(ClaimTypes.Name,userName)
                });
            tokenDescriptor.IssuedAt = DateTime.UtcNow;
            tokenDescriptor.Expires = now.AddMinutes(Convert.ToInt32(expireMinutes));
            tokenDescriptor.SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKeys),SecurityAlgorithms.HmacSha256Signature);
            var SecurityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(SecurityToken);
            return token;
        }
        public Task<ClaimsPrincipal>  GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
                if (jwtToken==null)
                {
                    return null;
                }
                var symmetrickeys = Convert.FromBase64String(Secret);
                var validationParameter = new TokenValidationParameters()
                {
                    ValidateIssuer=false,
                    ValidateAudience=false,
                    RequireExpirationTime=true,
                    IssuerSigningKey=new SymmetricSecurityKey(symmetrickeys)
                };
                SecurityToken securityToken;
                var principal = tokenHandler.ValidateToken(token, validationParameter,out securityToken);
                //var jwtSecurityToekn = tokenHandler.
                return Task.FromResult(principal);
            }
            catch (Exception)
            {

                return Task.FromResult<ClaimsPrincipal>(null);//important to keep
            }
        }
    }
}