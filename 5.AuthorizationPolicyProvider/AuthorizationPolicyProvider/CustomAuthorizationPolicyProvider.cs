using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace _1.Basis.AuthorizationPolicyProvider
{
    //Learn it from diffeent source???
    public static class DynamicPolicies
    {

        public static IEnumerable<string> Get()
        {
            yield return SecurityLevel;
            yield return Rank;
        }
        public const string SecurityLevel = "SecurityLevel";
        public const string Rank = "Rank";
    }
    public class CustomAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        public CustomAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
        {
        }

        //IAuthorizationPolicyProvider  - has four method bu we need only one for our sample, 
        //so we use DefaultAuthorizationPolicyProvider


        public override  Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {

            return base.GetPolicyAsync(policyName);
        }
    }
}
