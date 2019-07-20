using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace AuthNFilter2.Filters
{
    public class AuthenticationFilter:Attribute,IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }

        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var header = context.Request.Headers;
            var parameter = header.Authorization.Parameter;
            var scheme = header.Authorization.Scheme;
            Encoding encoding = Encoding.UTF8;
            byte[] encodedCreds = Convert.FromBase64String(parameter);
            string[] decodedCreds = encoding.GetString(encodedCreds).Split(':');
            string username = decodedCreds[0];
            string password = decodedCreds[1];
            //for valid Request username==password
            if (username.Equals(password,StringComparison.OrdinalIgnoreCase))
            {
                context.Principal = await GetClaims(username,password,cancellationToken);
            }
            else
            {
                context.ErrorResult = new AuthenticationFailedRequest("Unauthorised user",context.Request);
            }

        }
        public Task<ClaimsPrincipal> GetClaims(string username,string password,CancellationToken cancellationToken)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,username),
                new Claim("Password",password),
                new Claim(ClaimTypes.Email,username+"_92@gmail.com"),
                new Claim(ClaimTypes.StreetAddress,username+" Address"),
            };
            ClaimsIdentity id = new ClaimsIdentity(claims, "Basic");
            ClaimsPrincipal principal = new ClaimsPrincipal(new[] { id});
            return Task.FromResult(principal);
        }
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var headerValue = new AuthenticationHeaderValue("Basic");
            context.Result = new AddChallegeOnUnauthorised(headerValue,context.Result);
            return Task.FromResult(0);
        }
    }

    public class AddChallegeOnUnauthorised : IHttpActionResult
    {
        public AuthenticationHeaderValue Challenge { get; set; }
        public IHttpActionResult InnerResult { get; set; }
        public AddChallegeOnUnauthorised(AuthenticationHeaderValue challenge, IHttpActionResult innerResult)
        {
            this.Challenge = challenge;
            this.InnerResult = innerResult;
        }
        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            HttpResponseMessage response = await InnerResult.ExecuteAsync(cancellationToken);
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                response.Headers.WwwAuthenticate.Add(Challenge);
            }
            return response;
        }
    }

    public class AuthenticationFailedRequest : IHttpActionResult
    {
        public string Reason { get; set; }
        public HttpRequestMessage RequestMsg { get; set; }
        public AuthenticationFailedRequest(string Reason, HttpRequestMessage RequestMsg)
        {
            this.Reason = Reason;
            this.RequestMsg = RequestMsg;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(ExecuteErrorResponse());
        }
        private HttpResponseMessage ExecuteErrorResponse()
        {
            HttpResponseMessage httpResponseError = new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            return httpResponseError;
        }
    }
}