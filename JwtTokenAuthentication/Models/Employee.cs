using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace JwtTokenAuthentication.Models
{
    public class Employee
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Address { get; set; }
        public bool IsAdmin { get; set; }
        public bool IsHr { get; set; }
    }
}