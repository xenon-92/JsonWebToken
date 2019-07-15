using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http;

namespace JwtThroughDelegatingHandler.Controllers
{
    public class LoginController : ApiController
    {
        [HttpPost]
        public HttpResponseMessage Login()
        {
            var headers = Request.Headers;
            var scheme = headers.Authorization.Scheme;
            var parameter = headers.Authorization.Parameter;
            if (headers!=null && scheme.Equals("Basic",StringComparison.OrdinalIgnoreCase) && parameter!=null)
            {
                Encoding encoding = Encoding.ASCII;
                byte[] credentials = Convert.FromBase64String(parameter);
                string[] decodedCredentials = encoding.GetString(credentials).Split(':');
                string userName = decodedCredentials[0];
                string password = decodedCredentials[1];
                if (CheckUser(userName, password))
                {
                    string token = Jwtmanager.GenerateToken(userName,Request);
                    headers.Remove("Authorization");
                    headers.Add("Authorization","Bearer "+ token);
                    return Request.CreateResponse(HttpStatusCode.OK, token);
                }
                return Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "Unauthorised User");
            }
            return Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "Unauthorised User");
          }
        private bool CheckUser(string userName,string password)
        {
            //check db
            return true;
        }
    }
}
