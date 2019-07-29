using System.Collections.Generic;
using IdentityServer4.Models;
using Microsoft.Extensions.Configuration;

namespace Moneteer.Identity
{
    public static class IdentityConfig
    {
        public static IEnumerable<IdentityResource> IdentityResources = new List<IdentityResource>
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
        };

        public static IEnumerable<ApiResource> GetApiResources(IConfiguration configuration)
        {
            return new List<ApiResource>
            {
                new ApiResource("moneteer-api", "Moneteer API")
                {
                    ApiSecrets = { new Secret(configuration["ApiSecret"].Sha256()) }
                }
            };
        }
    }
}
