using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Server.Controllers
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
        public IActionResult Authenticate()
        {
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("granny", "cookie"),
                new Claim(ClaimTypes.Role, "Staff")
            };
            //Goto Definition of SigningCredentials and right click on SecurityKey and 
            //press F1 will take you to Microsoft help SecurityKey and we can grab one key from the
            // listed keys. 
            //1. Microsoft.IdentityModel.Tokens.AsymmetricsSecurityKey, 
            //2. Microsoft.IdentityModel.Tokens.JsonWebKey
            //3. Microsfot.IdentityModel.Tokens.SymmetricSecurityKey

            var secretBytes = Encoding.UTF8.GetBytes(Constants.Secret);
            var key = new SymmetricSecurityKey(secretBytes);
            var algorithm = SecurityAlgorithms.HmacSha256;
            var signingCredentials = new SigningCredentials(key, algorithm);

            var token = new JwtSecurityToken(
                    Constants.Issuer, 
                    Constants.Audiance,
                    claims,
                    notBefore : DateTime.Now,
                    expires : DateTime.Now.AddHours(1),
                    signingCredentials
                );

            var toekJson = new JwtSecurityTokenHandler().WriteToken(token);
            return Ok(new { accessToken = toekJson });
        }

        public IActionResult Decode(string part)
        {
            //Here we have to give part of the Jwttoken not full
            var bytes = Convert.FromBase64String(part);
            return Ok(Encoding.UTF8.GetString(bytes));
        }
    }
}
