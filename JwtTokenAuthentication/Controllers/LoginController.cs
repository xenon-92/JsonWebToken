using JwtTokenAuthentication.JWTManger;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace JwtTokenAuthentication.Controllers
{
    public class LoginController : ApiController
    {
        [AllowAnonymous]
        [HttpGet]
        public HttpResponseMessage Login()
        {
            var headers = Request.Headers;
            string parameter = headers?.Authorization?.Parameter;
            string scheme = headers?.Authorization?.Scheme;
            if ((!scheme.Equals("Basic",StringComparison.OrdinalIgnoreCase)) && parameter == null)
            {
                return Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "Unauthorised User");
            }
            Encoding encode = Encoding.UTF8;
            byte[] encodedCreds = Convert.FromBase64String(parameter);
            string[] decodedCreds = encode.GetString(encodedCreds).Split(':');
            string username = decodedCreds[0];
            string password = decodedCreds[1];
            if (CheckUser(username,password))
            {
                string jwt= JWTHandler.GenerateToken(username);
                //headers.Remove("Authorization");
                headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer",jwt);
                return Request.CreateResponse(HttpStatusCode.OK, jwt);
            }
            return Request.CreateErrorResponse(HttpStatusCode.Unauthorized,"Unauthorised User");
        }
        private bool CheckUser(string username,string password)
        {
            //check db
            if (username.Equals(password,StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            return false;
        }
    }
    
}
