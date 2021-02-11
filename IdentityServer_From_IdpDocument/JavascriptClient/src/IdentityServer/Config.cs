
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            { 
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource("customprofile","Custom Profile", new List<string>{"userstatus","email"})
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new List<ApiScope>
            { new ApiScope("api1", "My API")
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                new Client
                {
                    ClientId = "client",

                    //No interact users so use the clientid/secret for authentication
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret("secret".Sha256())
                    },
                    AllowedScopes = {"api1" }
                },
                new Client
                {
                    ClientId="mvc",
                    ClientSecrets = {new Secret("secret".Sha256())},
                    AllowedGrantTypes = GrantTypes.Code,
                    //where to redirect after login
                    RedirectUris = {"https://localhost:44389/signin-oidc" },
                    //where to redirect after logout
                    PostLogoutRedirectUris = { "https://localhost:44389/signout-callback-oidc" },
                    AllowOfflineAccess = true, // enable refresh token
                    AllowedScopes = new List<string>
                    { 
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        //IdentityServerConstants.StandardScopes.Email,
                         "api1"
                        //"customprofile"
                    }
                },
                new Client
                {
                    ClientId = "js",
                    ClientName = "JavaScript Client",
                    AllowedGrantTypes = GrantTypes.Code,
                    RequireClientSecret = false,

                    RedirectUris =           { "http://localhost:55021/callback.html" },
                    PostLogoutRedirectUris = { "http://localhost:55021/index.html" },
                    AllowedCorsOrigins =     { "http://localhost:55021" },

                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "api1"
                    }
                }
            };
    }
}