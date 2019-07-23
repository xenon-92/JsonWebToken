using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;
using System.Web.Http;
using TokenBasedAuthentication_JWT.AuthorizationManager;

namespace TokenBasedAuthentication_JWT.Controllers
{
    public class LoginController : ApiController
    {
        private string username { get; set; }
        private string password { get; set; }

        [AllowAnonymous]
        [HttpGet]
        public HttpResponseMessage Login(string username,string password)
        {
            var ipaddress = HttpContext.Current.Request.UserHostAddress;            
            if (CheckCredentails(username,password))
            {
                TokenIssuer token = new TokenIssuer();
                string jwt_token = token.GenerateJWT(username, ipaddress);
                Request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer",jwt_token);
                return Request.CreateResponse(HttpStatusCode.OK, jwt_token);
            }
            return Request.CreateErrorResponse(HttpStatusCode.Unauthorized,new HttpError("Invalid Credentails"));
        }

        private bool CheckCredentails(string username,string password)
        {
            this.username = username;
            this.password = password;
            if (this.username.Equals(this.password,StringComparison.OrdinalIgnoreCase))
            {
                //to do apply salting and hashing of password
                //retrieve db for authentication of username to mapped password
                //https://stackoverflow.com/questions/4181198/how-to-hash-a-password/10402129#10402129
                return true;
            }
            return false;
        }
        
    }
}
