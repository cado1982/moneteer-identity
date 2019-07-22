using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Moneteer.Identity.Extensions
{
    public static class IdentityServerBuliderExtensions
    {
        public static IIdentityServerBuilder LoadSigningCredential(this IIdentityServerBuilder builder, IHostingEnvironment environment, IConfiguration configuration)
        {
            if (environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                var cert = GetSigningCertificate(configuration);

                if (cert == null)
                {
                    throw new Exception("Unable to retrieve identity server token signing cert");
                }

                builder.AddSigningCredential(cert);
            }

            return builder;
        }

        private static X509Certificate2 GetSigningCertificate(IConfiguration configuration)
        {
            var cert = configuration["TokenSigningCert"];
            var secret = configuration["TokenSigningCertSecret"];
                
            byte[] decodedPfxBytes = Convert.FromBase64String(cert);
            return new X509Certificate2(decodedPfxBytes, secret);
        }
    }
}
