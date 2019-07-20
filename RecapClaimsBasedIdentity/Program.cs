using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RecapClaimsBasedIdentity
{
    class Program
    {
        static void Main(string[] args)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,"Tudu"),
                new Claim(ClaimTypes.Email,"Tudu"),
                new Claim(ClaimTypes.Role,"Tudu"),
                new Claim(ClaimTypes.MobilePhone,"Tudu"),
                new Claim(ClaimTypes.StreetAddress,"Tudu"),
            };
            var id = new ClaimsIdentity(claims,"dumm");
            var principal = new ClaimsPrincipal(new[] { id});
            Thread.CurrentPrincipal = principal;
            ClaimsPrincipal p = Display();
        }
        static ClaimsPrincipal Display()
        {
            ClaimsPrincipal principal = Thread.CurrentPrincipal as ClaimsPrincipal;
            return principal;
        }
    }
}
