﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace _1.Basis.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        public void CheckUser()
        {
            var user = HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Name).FirstOrDefault();
            Response.WriteAsync(user.Value);
        }
        public IActionResult Authenticate()
        {
            var grandmaClaims = new List<Claim> {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@fmail.com"),
                new Claim("Grandma.Says", "Very Nice Boy")
            };

            var licenseClaims = new List<Claim> {
                new Claim(ClaimTypes.Name, "Bob K Foo"),
                new Claim("DrivingLicense", "A+")
            };

            var grandmaIdentity = new ClaimsIdentity(grandmaClaims, "Grandma Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "Government");

            var userPrincipal = new ClaimsPrincipal(new[] { grandmaIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);
            //HttpContext.User
            return RedirectToAction("Index");
        }

    }
}
