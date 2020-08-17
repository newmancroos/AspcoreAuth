using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace _1.Basis.Controllers
{
    public class HomeController : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public HomeController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Secret()
        {
            return View();
        }

        [Authorize(Policy = "Claim.DoB")]
        public IActionResult SecretPolicy()
        {
            return View("Secret");
        }

        [Authorize(Roles = "Admin")]
        public IActionResult SecretAdmin()
        {
            return View("Secret");
        }

        public void CheckUser()
        {
            var user = HttpContext.User.Claims.Where(x => x.Type == ClaimTypes.Name).FirstOrDefault();
            Response.WriteAsync(user.Value);
        }
        [AllowAnonymous]
        public IActionResult Authenticate()
        {
            var grandmaClaims = new List<Claim> {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@fmail.com"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("Grandma.Says", "Very Nice Boy"),
                //new Claim(ClaimTypes.DateOfBirth, "06/19/1973")
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

        public async Task<IActionResult> DoStuff() {
            //Do any stuff here

            var builder = new AuthorizationPolicyBuilder("Schema");
            var customPolicy = builder.RequireClaim("Hello").Build();
            var authResult = await _authorizationService.AuthorizeAsync(User, customPolicy);
            if (authResult.Succeeded)
            { 
                //Authorization success
            }
            
            //await _authorizationService.AuthorizeAsync(User, "Claim.DoB");
            return View("Index");
        }
        public async Task<IActionResult> DoStuff_FuncInject([FromServices] IAuthorizationService authService)
        {
            //Do any stuff here

            var builder = new AuthorizationPolicyBuilder("Schema");
            var customPolicy = builder.RequireClaim("Hello").Build();
            var authResult = await authService.AuthorizeAsync(User, customPolicy);
            if (authResult.Succeeded)
            {
                return View("Index");
            }

            //await _authorizationService.AuthorizeAsync(User, "Claim.DoB");
            return View("Index");
        }
    }
}
