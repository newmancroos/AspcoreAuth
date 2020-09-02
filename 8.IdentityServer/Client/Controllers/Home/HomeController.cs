using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace Client.Home.Controllers
{
    public class HomeController : Controller
    {
        public readonly IHttpClientFactory _httpClientFactory;
        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }
        public IActionResult Index()
        {
            return View();
        }

        //[Authorize]
        //public async Task<IActionResult> Secret()
        //{
        //    var token = await HttpContext.GetTokenAsync("access_token");
        //    var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        //    //HttpContext.User.HasClaim(c => c.Type =="granny");
        //    var serverClient = _httpClientFactory.CreateClient();
        //    serverClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        //    var serverResponse = await serverClient.GetAsync("https://localhost:44382/secret/index");
        //    //---Refresh token related---------------------------------------
        //    //Because of expire in millisecodn and ClockSkew = TimeSpan.Zero we will get 401 Unauthorized here
        //    // So we are ready to request for the token using refresh token. 
        //    //----------------------------------------------------------------

        //    await RefreshAccessToken();

        //    token = await HttpContext.GetTokenAsync("access_token");
        //    var apiClient = _httpClientFactory.CreateClient();
        //    apiClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        //    //Call Api
        //    //Cal the server if no authentication it will automatically redirect to login page, and get the 
        //    // Access code and then Access token in the above step and now it will pass the access token to the api.
        //    var apiResponse = await apiClient.GetAsync("https://localhost:44339/secret/index");

        //    return View();
        //}


        //public async Task RefreshAccessToken()
        //{
        //    var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        //    var refreshTokenClient = _httpClientFactory.CreateClient();

        //    var requestData = new Dictionary<string, string>()
        //    {
        //        ["grant_type"] = "refresh_token",
        //        ["refresh_token"] = refreshToken
        //    };

        //    var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost:44382/oauth/token")
        //    {
        //        Content = new FormUrlEncodedContent(requestData)
        //    };
        //    var basicCrdential = "username:password";
        //    var encodedCredential = Encoding.UTF8.GetBytes(basicCrdential);
        //    var base64Credential = Convert.ToBase64String(encodedCredential);

        //    request.Headers.Add("Authorization", $"Basic {base64Credential}");
        //    var response = await refreshTokenClient.SendAsync(request);

        //    var responseString = await response.Content.ReadAsStringAsync();
        //    var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);
        //    var newAccessToken = responseData.GetValueOrDefault("access_token");
        //    var newRefreshToken = responseData.GetValueOrDefault("refresh_token");

        //    //--------------------------Reqwrite the authorization priciples----------------------
        //    //Bring all the Authentication information
        //    var authInfo = await HttpContext.AuthenticateAsync("ClientCookie");
        //    authInfo.Properties.UpdateTokenValue("access_token", newAccessToken);
        //    authInfo.Properties.UpdateTokenValue("refresh_token", newRefreshToken);
        //    await HttpContext.SignInAsync("ClientCookie", authInfo.Principal, authInfo.Properties);
        //    //------------------------------------------------------------------------------------
        //}

        //-----------------------Begin - Refactor Secret Method cmmented code--------------------------
        [Authorize]
        public async Task<IActionResult> Secret()
        {
            var serverResponse = await AccessTokenRefreshWrapper(
                () => SecureGetRequest("https://localhost:44382/secret/index"));

            var apiResponse = await AccessTokenRefreshWrapper(
                () => SecureGetRequest("https://localhost:44339/secret/index"));
            return View();
        }

        private async Task<HttpResponseMessage> SecureGetRequest(string url)
        {
            var token = await HttpContext.GetTokenAsync("access_token");
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
            return await client.GetAsync(url);
        }

        public async Task<HttpResponseMessage> AccessTokenRefreshWrapper(
            Func<Task<HttpResponseMessage>> initialRequest)
        {
            var response = await initialRequest();

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                await RefreshAccessToken();
                response = await initialRequest();
            }

            return response;
        }
        public async Task RefreshAccessToken()
        {
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            var refreshTokenClient = _httpClientFactory.CreateClient();

            var requestData = new Dictionary<string, string>()
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "https://localhost:44382/oauth/token")
            {
                Content = new FormUrlEncodedContent(requestData)
            };
            var basicCrdential = "username:password";
            var encodedCredential = Encoding.UTF8.GetBytes(basicCrdential);
            var base64Credential = Convert.ToBase64String(encodedCredential);

            request.Headers.Add("Authorization", $"Basic {base64Credential}");
            var response = await refreshTokenClient.SendAsync(request);

            var responseString = await response.Content.ReadAsStringAsync();
            var responseData = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseString);
            var newAccessToken = responseData.GetValueOrDefault("access_token");
            var newRefreshToken = responseData.GetValueOrDefault("refresh_token");

            //--------------------------Reqwrite the authorization priciples----------------------
            //Bring all the Authentication information
            var authInfo = await HttpContext.AuthenticateAsync("ClientCookie");
            authInfo.Properties.UpdateTokenValue("access_token", newAccessToken);
            authInfo.Properties.UpdateTokenValue("refresh_token", newRefreshToken);
            await HttpContext.SignInAsync("ClientCookie", authInfo.Principal, authInfo.Properties);
            //------------------------------------------------------------------------------------
        }

        //-----------------------End - Refactor Secret Method cmmented code--------------------------
    }

}
