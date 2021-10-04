using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Server.Controllers
{
    public class SecretController : Controller
    {
        [Authorize(Roles ="Staff1")]
        public string Index()
        {
            return "Secret Message";
        }
    }
}
