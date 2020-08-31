using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;

namespace Client.Home.Controllers
{
    public class HomeController : Controller
    {
        public readonly IHttpClientFactory _httpClientFactory;
        private readonly HttpClient _client;
        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
            _client = _httpClientFactory.CreateClient();
        }
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Secret()
        {
            var token = await HttpContext.GetTokenAsync("access_token");
            //HttpContext.User.HasClaim(c => c.Type =="granny");
            _client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            var serverResponse = await _client.GetAsync("https://localhost:44382/secret/index");

            //Call Api
            var apiResponse = await _client.GetAsync("https://localhost:44339/secret/index");
                        
            return View();
        }

        [Authorize]
        public IActionResult MyTest()
        {
            return View();
        }
    }
}
