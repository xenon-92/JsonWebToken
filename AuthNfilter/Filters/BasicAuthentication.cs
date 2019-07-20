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

namespace AuthNfilter.Filters
{
    public class BasicAuthentication : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple { get { return false; } }
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var request = context.Request;
            var header = request.Headers;
            if (header.Authorization == null)
            {
                return;
            }
            if (header.Authorization.Scheme != "Basic")
            {
                return;
            }
            if (string.IsNullOrEmpty(header.Authorization.Parameter))
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing Credentials",request);
            }
            string encodedCreds = request.Headers.Authorization.Parameter;
            Encoding encoding = Encoding.UTF8;
            byte[] credsinBytes = Convert.FromBase64String(encodedCreds);
            string[] decodedCreds = encoding.GetString(credsinBytes).Split(':');
            string userName = decodedCreds[0];
            string password = decodedCreds[1];
            if (userName == null || password==null)
            {
                context.ErrorResult = new AuthenticationFailureResult("credentials or username is missing", request);
            }  
            //check db for username and password
            if (userName==password)
            {
                context.Principal = await sometask(userName,password,cancellationToken);
            }
            else
            {
                context.ErrorResult = new AuthenticationFailureResult("wrong crdentials",request);
            }
        }
        public /*async*/ Task<ClaimsPrincipal> sometask(string username,string password, CancellationToken cancellationToken)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,username),
                new Claim("Password",password),
                new Claim(ClaimTypes.Role,"Norole"),
            };
            ClaimsIdentity identity = new ClaimsIdentity(claims,"Normal");
            ClaimsPrincipal principal = new ClaimsPrincipal(new[] { identity});
            return Task.FromResult(principal);
        }
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            var challenge = new AuthenticationHeaderValue("Basic");
            context.Result = new AddChallengeOnUnauthorizedResult(challenge,context.Result);
            return Task.FromResult(0);
        }
    }

    public class AuthenticationFailureResult: IHttpActionResult
    {
        private string ReasonPhrase { get; set; }
        private HttpRequestMessage Request { get; set; }
        public AuthenticationFailureResult(string reasonPhrase,HttpRequestMessage request)
        {
            this.ReasonPhrase = reasonPhrase;
            this.Request = request;
        }
        public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Execute());
        }
        private HttpResponseMessage Execute()
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            return response;
        }
    }
    public class AddChallengeOnUnauthorizedResult: IHttpActionResult
    {
        private AuthenticationHeaderValue challenge { get; set; }
        private IHttpActionResult InnerResult { get; set; }
        public AddChallengeOnUnauthorizedResult(AuthenticationHeaderValue challenge, IHttpActionResult result)
        {
            this.challenge = challenge;
            this.InnerResult = result;
        }
        public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
        {
            HttpResponseMessage response = await InnerResult.ExecuteAsync(cancellationToken);
            /*
             * //hits controller and action method for valid credentials
             * and hits AuthenticationFailureResult's ExecuteAsync for invalid credentials
            */
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                if (!response.Headers.WwwAuthenticate.Any(h=>h.Scheme==challenge.Scheme))
                {
                    response.Headers.WwwAuthenticate.Add(challenge);
                }
            }
            return response;
        }
    }
}