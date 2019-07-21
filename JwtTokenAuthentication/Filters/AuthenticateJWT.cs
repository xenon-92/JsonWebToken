using JwtTokenAuthentication.JWTManger;
using JwtTokenAuthentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace JwtTokenAuthentication.Filters
{
    public class AuthenticateJWT:Attribute,IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var headers = context.Request.Headers;
            
            var scheme = headers?.Authorization?.Scheme;
            var parameter = headers?.Authorization?.Parameter;
            if (scheme == null || parameter==null)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Header not found", context.Request);
                return;
            }
            if (!scheme.Equals("Bearer",StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(parameter))
            {
                context.ErrorResult = new AuthenticationFailureRequest("Token not found", context.Request);
                return;
            }
            JWTHandler handler = new JWTHandler();
            var principal = await handler.GetPrincipal(parameter);
            if (principal == null)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Claims not found",context.Request);
                return;
            }
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            if (identity == null)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Identity not found",context.Request);
                return;
            }
            if (!identity.IsAuthenticated)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Not authenticated",context.Request);
                return;
            }
            var userClaim = identity.FindFirst(ClaimTypes.Name);
            var userName = userClaim?.Value;
            if (string.IsNullOrEmpty(userName))
            {
                context.ErrorResult = new AuthenticationFailureRequest("No UserName found",context.Request);
                return;
            }
            else
            {
                //check db for the user name and if it exists bring back the other essential claims such as
                //email,address,isAdmin,Department
                ClaimsPrincipal Allprincipal = await GetAdditionalClaims(userName,cancellationToken);
                if (Allprincipal!=null)
                {
                    context.Principal = Allprincipal;
                    var x = Thread.CurrentPrincipal;
                    return;
                }
                else
                {
                    context.ErrorResult = new AuthenticationFailureRequest("UserName is not Valid", context.Request);
                }
            }
        }
        public Task<ClaimsPrincipal> GetAdditionalClaims(string username,CancellationToken cancellationToken)
        {
            //mocking the db//
            List<Employee> employees = new List<Employee>()
            {
                new Employee{UserName="Tudu",Email="tudu@gmail.com",Address="Cochbehar",IsAdmin=true,IsHr=false},//admin
                new Employee{UserName="gaffu",Email="gaffu@gmail.com",Address="Dinajpur",IsAdmin=false,IsHr=false},
                new Employee{UserName="mosa",Email="mosa@gmail.com",Address="hwh",IsAdmin=false,IsHr=true},//hr
                new Employee{UserName="mohar",Email="mohar@gmail.com",Address="park circus",IsAdmin=false,IsHr=false},
                new Employee{UserName="Aslam",Email="aslu@gmail.com",Address="not in db",IsAdmin=false,IsHr=false},
                new Employee{UserName="homo",Email="homo@gmail.com",Address="nayahati",IsAdmin=true,IsHr=true}//admin,hr
            };
            //end of mocking db
            bool ifExists = false;
            List<Claim> claims = null;
            foreach (var v in employees)
            {
                if (v.UserName.Equals(username,StringComparison.OrdinalIgnoreCase))
                {
                    claims = new List<Claim>()
                    {
                        new Claim(ClaimTypes.Name,v.UserName),
                        new Claim(ClaimTypes.Email,v.Email),
                        new Claim(ClaimTypes.StreetAddress,v.Address),
                        new Claim("IsAdmin",Convert.ToString(v.IsAdmin)),
                        new Claim("IsHr",Convert.ToString(v.IsHr)),
                    };
                    ifExists = true;
                    break;
                }
                //ifExists = false;
            }
            if (ifExists)
            {
                ClaimsIdentity id = new ClaimsIdentity(claims, "jwt");
                ClaimsPrincipal principal = new ClaimsPrincipal(new[] { id});
                return Task.FromResult(principal);
            }
            return null;

        }
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var headerValue = new AuthenticationHeaderValue("Bearer");
            context.Result = new AddChallengeOnUnauthorised(headerValue,context.Result);
            return Task.FromResult(0);
        }
    }

    public class AuthenticationFailureRequest : IHttpActionResult
    {
        private string Reason { get; set; }
        private HttpRequestMessage Request { get; set; }
        public AuthenticationFailureRequest(string Reason, HttpRequestMessage Request)
        {
            this.Reason = Reason;
            this.Request = Request;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(ExecuteErrorResponse());
        }
        private HttpResponseMessage ExecuteErrorResponse()
        {
            HttpResponseMessage response = new HttpResponseMessage()
            {
                Content = new StringContent(Reason),
                StatusCode = System.Net.HttpStatusCode.Unauthorized,
            };
            return response;
        }
    }
    public class AddChallengeOnUnauthorised : IHttpActionResult
    {
        private AuthenticationHeaderValue Challenge { get; set; }
        private IHttpActionResult InnerResult { get; set; }
        public AddChallengeOnUnauthorised(AuthenticationHeaderValue Challenge, IHttpActionResult InnerResult)
        {
            this.Challenge = Challenge;
            this.InnerResult = InnerResult;
        }
        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            HttpResponseMessage response = await InnerResult.ExecuteAsync(cancellationToken);
            if (response.StatusCode==System.Net.HttpStatusCode.Unauthorized)
            {
                response.Content = new StringContent("Unauthorised user");
                response.Headers.WwwAuthenticate.Add(Challenge);
            }
            return response;
        }

    }
}