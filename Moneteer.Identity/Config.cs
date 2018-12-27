using System.Collections.Generic;
using IdentityServer4;
using IdentityServer4.Models;

namespace Moneteer.Identity
{
    public static class Config
    {
        public static IEnumerable<Client> Clients = new List<Client>
        {
            new Client
            {
                ClientId = "moneteer-spa",
                AllowedGrantTypes = GrantTypes.Implicit,
                AllowAccessTokensViaBrowser = true,
                RequireClientSecret = false,
                RequireConsent = false,
                RedirectUris = {
                    "https://localhost:4200/auth-callback",
                    "https://localhost:4200/silent-callback"
                },
                PostLogoutRedirectUris = { "https://localhost:4200/" },
                AccessTokenLifetime = 3600,
                IdentityTokenLifetime = 300,
                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "moneteer-api"
                },
                AllowedCorsOrigins = { "https://localhost:4200" }
            },
            new Client
            {
                ClientId = "moneteer-mvc",
                ClientName = "MVC Client",
                AllowedGrantTypes = GrantTypes.Implicit,
                RequireConsent = false,
                
                RedirectUris = { "https://localhost:4500/signin-callback-oidc" },
                PostLogoutRedirectUris = { "https://localhost:4500/signout-callback-oidc" },

                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                },
            }
        };

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
