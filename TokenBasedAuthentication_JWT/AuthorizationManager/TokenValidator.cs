using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;

namespace TokenBasedAuthentication_JWT.AuthorizationManager
{
    public class TokenValidator:Attribute, IAuthenticationFilter
    {
        bool AllowMultiple { get { return false; } }
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var headers = context.Request.Headers;
            var parameter = headers?.Authorization?.Parameter;
            var scheme = headers?.Authorization?.Scheme;
            if (parameter==null || scheme==null)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Authorization scheme or parameter is missing",context.Request);
                return;
            }
            if ( string.IsNullOrEmpty(parameter)|| (!scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)))
            {
                context.ErrorResult = new AuthenticationFailureRequest("Parameter not found", context.Request);
                return;
            }
            TokenDecryptor decryptor = new TokenDecryptor();
            var principal = decryptor.GetPrincipal(parameter);
            if (principal==null)
            {
                context.ErrorResult = new AuthenticationFailureRequest("Claims not found", context.Request);
                return;
            }
        }


    }
    class AuthenticationFailureRequest: IHttpActionResult
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
                StatusCode = System.Net.HttpStatusCode.Unauthorized,
                Content = new StringContent(Reason)
            };
            return response;
        }
    }
}