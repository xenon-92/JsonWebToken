using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JwtThroughDelegatingHandler
{
    public class AuthenticateJwtHandler:DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri.AbsoluteUri!= "http://localhost:52191/api/Login")
            {
                var requestHeader = request.Headers;
                var scheme = requestHeader.Authorization.Scheme;
                var token = requestHeader.Authorization.Parameter;
                if (requestHeader.Authorization == null || !scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase))
                {
                    var responsex = new HttpResponseMessage()
                    {
                        StatusCode = System.Net.HttpStatusCode.Unauthorized,
                        Content = new StringContent("Invalid User"),
                    };
                    return request.CreateResponse(System.Net.HttpStatusCode.Unauthorized, responsex);
                }
                if (string.IsNullOrEmpty(token))
                {
                    var responsex = new HttpResponseMessage()
                    {
                        StatusCode = System.Net.HttpStatusCode.Unauthorized,
                        Content = new StringContent("Invalid User"),
                    };
                    return request.CreateResponse(System.Net.HttpStatusCode.Unauthorized, responsex);
                }
                var principal = await AuthenticateJwtToken(token);
                Thread.CurrentPrincipal = principal;
                if (System.Web.HttpContext.Current != null)
                {
                    System.Web.HttpContext.Current.User = principal;
                }
            }
            var response = await base.SendAsync(request, cancellationToken);
            return response;
        }
        private Task<IPrincipal> AuthenticateJwtToken(string token)
        {
            string username;

            if (ValidateToken(token, out username))
            {
                // based on username to get more information from database in order to build local identity
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                    // Add more claims if needed: Roles, ...
                };

                var identity = new ClaimsIdentity(claims, "Jwt");
                IPrincipal user = new ClaimsPrincipal(identity);

                return Task.FromResult(user);
            }

            return Task.FromResult<IPrincipal>(null);
        }
        private static bool ValidateToken(string token, out string username)
        {
            username = null;

            var simplePrinciple = Jwtmanager.GetPrincipal(token);
            var identity = simplePrinciple?.Identity as ClaimsIdentity;

            if (identity == null)
                return false;

            if (!identity.IsAuthenticated)
                return false;

            var usernameClaim = identity.FindFirst(ClaimTypes.Name);
            username = usernameClaim?.Value;

            if (string.IsNullOrEmpty(username))
                return false;

            // More validate to check whether username exists in system

            return true;
        }
    }
}