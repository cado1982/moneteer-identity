using System.Collections.Generic;
using IdentityServer4;
using IdentityServer4.Models;

namespace Moneteer.Identity
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources = new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
        };

        public static IEnumerable<ApiResource> Apis = new List<ApiResource>
        {
            new ApiResource("moneteer-api", "Moneteer API")
            {
                ApiSecrets = { new Secret("eb18f78e-d660-448a-9e28-cae9790a2a2d".Sha256()) }
            }
        };
    }
}
