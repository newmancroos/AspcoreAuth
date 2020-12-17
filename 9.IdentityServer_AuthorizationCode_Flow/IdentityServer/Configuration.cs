using IdentityModel;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace IdentityServer
{
    public static  class Configuration
    {
        //an Api can be a Api and also Client,
        //Here ApiOne is the Api and ApiTwo is client
        public static IEnumerable<ApiResource> GetApis() =>
            new List<ApiResource> {new ApiResource("ApiOne"),new ApiResource("ApiTwo")
            };
        public static IEnumerable<Client> GetClients() =>
            new List<Client>
            {
                new Client{ 
                    ClientId = "client_id",
                    ClientSecrets = { new Secret("client_secret".ToSha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes ={ "ApiOne" }
                },
                new Client{
                    ClientId = "client_id_mvc",
                    ClientSecrets = { new Secret("client_secret_mvc".ToSha256()) },
                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = { "https://localhost:44392/signin-oidc"},
                    AllowedScopes ={ "ApiOne", "ApiTwo", 
                    IdentityServer4.IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServer4.IdentityServerConstants.StandardScopes.Profile,
                    }  // "openid" - we can put string like this or use constant
                }
            };

        public static List<IdentityResource> GetIdentityResources() =>
             new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile()
            };

        public static List<ApiScope> GetApiScopes() =>
         new List<ApiScope>
        {
                new ApiScope("ApiOne", "My API")
        };
    }
}
