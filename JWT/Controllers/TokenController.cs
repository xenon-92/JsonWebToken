﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace JWT.Controllers
{
    public class TokenController : ApiController
    {
        [AllowAnonymous]
        public string Get(string username,string password)
        {
            if (CheckUser(username,password))
            {
                return JwtManager.GenerateToken(username);
            }
            throw new HttpResponseException(HttpStatusCode.Unauthorized);
        }
        private bool CheckUser(string username,string password)
        {
            return true;
        }
    }
}
