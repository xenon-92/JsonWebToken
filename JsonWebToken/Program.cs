using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JsonWebToken
{
    class Program
    {
        static void Main(string[] args)
        {
            string key= "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1";
            var securityKeys = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Convert.FromBase64String(key));
            var credentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKeys,SecurityAlgorithms.HmacSha256Signature);

            var header = new JwtHeader(credentials);

            var payload = new JwtPayload
            {
                {"Name","Anuj" },
                {"Admin","false" },
            };
            //var signature = new jwtsi
            var sectoken = new JwtSecurityToken(header,payload);
            var handler = new JwtSecurityTokenHandler();
            var tokenString = handler.WriteToken(sectoken);

            Console.WriteLine(tokenString);
            //consuming
            var token = handler.ReadJwtToken(tokenString);
            Console.WriteLine(token.Payload.First().Value);
            Console.ReadLine();
        }
    }
}
