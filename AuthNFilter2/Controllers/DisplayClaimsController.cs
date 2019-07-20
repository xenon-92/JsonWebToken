using AuthNFilter2.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Web.Http;

namespace AuthNFilter2.Controllers
{
    [AuthenticationFilter]
    [Authorize]
    public class DisplayClaimsController : ApiController
    {
        [HttpGet]
        public HttpResponseMessage DisplayClaims()
        {
            ClaimsPrincipal principal = Thread.CurrentPrincipal as ClaimsPrincipal;
            ClaimsIdentity id = principal.Identity as ClaimsIdentity;
            //List<Claim> claims = id.Claims as List<Claim>;
            return Request.CreateResponse(HttpStatusCode.OK, id.Claims);
        }
    }
}
