using IdentityModel.Client;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace ApiTwo.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [Route("/")]
        public async Task<IActionResult> Index()
        {
            //Retrive Access token

            //This is going to be "Client Crdential flow"

            //Need to add a Nuget package IdentityModel
            var serverClient = _httpClientFactory.CreateClient();
            //Return discovery endpoints as the url https://localhost:44320/.well-known/openid-configuration
            var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync("https://localhost:44320/");

            //Token Response return something like access_token, token_type, raw_claim, refresh_token.
            var tokenResponse = await serverClient.RequestClientCredentialsTokenAsync(
                    new ClientCredentialsTokenRequest
                    {
                        Address = discoveryDocument.TokenEndpoint,
                        ClientId = "client_id",
                        ClientSecret = "client_secret",
                        Scope = "ApiOne",
                    }
                );

            //Retrive secret data
            var apiClient = _httpClientFactory.CreateClient();
            apiClient.SetBearerToken(tokenResponse.AccessToken);
            //apiClient.SetToken("bearer", tokenResponse.AccessToken);
            var response = await apiClient.GetAsync("https://localhost:44356/secret");

            var content = await response.Content.ReadAsStringAsync();
            //We get content as empty, as per tutorial they advice to degrade Identity server from 4.x.x to 3.0.2 
            return Ok(new
            {
                access_token = tokenResponse.AccessToken,
                message = content
            });
        }


    }
}
