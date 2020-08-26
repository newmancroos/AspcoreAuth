using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Server.Controllers
{
    public class OAuthController : Controller
    {
        [HttpGet]
        public IActionResult Authorize(
            string response_type, //Authorization flow type
            string client_id,  //Client id
            string redirect_uri, // Client uri where user try to browse
            string scope, //what information I want ex. email, phone, grandma cookie...
            string state // randon string generted to confirm that we are going back to the same client
            )
        {
            var query = new QueryBuilder();
            query.Add("redirectUri", redirect_uri);
            query.Add("state", state);
            return View(model: query.ToString()); //?a=foo&b=bar format
        }

        [HttpPost]
        public IActionResult Authorize(string userName, string redirecturi, string state)
        {
            //We need some parameter for Authorization request from Get method so we pass it to this method too.
            //This methd should redirect to client with Code and state
            var code = "DJDKJKDJKJKJDJDKJ";
            var query = new QueryBuilder();
            query.Add("code", code);
            query.Add("state", state);
            return Redirect($"{redirecturi}{query.ToString()}");
        }
        public async Task<IActionResult> Token(
            string grant_type,  //flow of access_token request 
            string code, //Confirmation of the authentication process
            string redirect_uri, 
            string client_id)
        {
            //this method should return Json response that contain the following
            //"access_token, token_type, expire_in, refresh_token, example_parameter"

            //Some mechanism for validating the code, usualy save the code in database and validate it.

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, "some_id"),
                new Claim("granny", "cookie"),
                new Claim("Role", "Staff")
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
                    notBefore: DateTime.Now,
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials
                );

            var access_token = new JwtSecurityTokenHandler().WriteToken(token);
            var responseObject = new
            {
                access_token,
                token_type="Bearer",
                raw_claim="oauthTutorial" //example parameter
            };

            var responseJson = JsonConvert.SerializeObject(responseObject);
            var responseBytes = Encoding.UTF8.GetBytes(responseJson);

            await Response.Body.WriteAsync(responseBytes,0, responseBytes.Length);
            return Redirect(redirect_uri);
        }
    }
}
