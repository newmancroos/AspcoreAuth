using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace _1.Basis.Controllers
{
    public class OperationController : Controller
    {
        private readonly  IAuthorizationService _authorizationService;

        public OperationController(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
        }

        public async Task<IActionResult> Open()
        {
            var requirement = new OperationAuthorizationRequirement
            {
                Name = CookieJarOperations.ComeNear
            };

            CookiJarResource resource = new CookiJarResource { Name = "Open" };
            //await _authorizationService.AuthorizeAsync(User, null, requirement);
            await _authorizationService.AuthorizeAsync(User, resource, requirement);
            //Second parameter(resource) is optional but we can pass if any and need to specify this in the AuthorizationHandler

            return View();
        }

    }
    public class CookieJarAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, CookiJarResource>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, 
            OperationAuthorizationRequirement requirement, CookiJarResource resource)
        {

            //You can check resource for anyrequirement if you have
            if (requirement.Name == CookieJarOperations.Look)
            {
                if (context.User.Identity.IsAuthenticated)
                {
                    context.Succeed(requirement);
                }
            }
            else if (requirement.Name == CookieJarOperations.ComeNear)
            {
                if (context.User.HasClaim("Friend","GoodFriend"))
                {
                    context.Succeed(requirement);
                }
            }
            else if (requirement.Name == CookieJarOperations.Look)
            { 
            }

            return Task.CompletedTask;
        }
    }

    public static class CookieJarOperations {
        public static string Open = "Open";
        public static string TakeCookie = "TakeCookie";
        public static string ComeNear = "ComeNear";
        public static string Look = "Look";
    }

    public class CookiJarResource
    {
        public string Name { get; set; }
    }
}
