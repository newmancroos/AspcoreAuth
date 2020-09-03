using IdentityModel;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer
{
    public static  class Configuration
    {
        //an Api can be a Api and also Client,
        //Here ApiOne is the Api and ApiTwo is client
        public static IEnumerable<ApiResource> GetApis() =>
            new List<ApiResource> {new ApiResource("ApiOne") 
            };
        public static IEnumerable<Client> GetClients() =>
            new List<Client>
            {
                new Client{ 
                    ClientId = "client_id",
                    ClientSecrets = { new Secret("client_secret".ToSha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes ={ "ApiOne" }
                }
            };

        //public static List<IdentityResource> GetIdentityResources() =>
        //     new List<IdentityResource>
        //    {
        //        new IdentityResources.OpenId(),
        //        new IdentityResources.Profile()
        //    };

        public static List<ApiScope> GetApiScopes() =>
         new List<ApiScope>
        {
                new ApiScope("ApiOne", "My API")
        };
    }
}
