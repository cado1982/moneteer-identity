using System;
using System.Security.Cryptography.X509Certificates;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Moneteer.Identity.Extensions
{
    public static class IdentityServerBuliderExtensions
    {
        public static IIdentityServerBuilder LoadSigningCredential(this IIdentityServerBuilder builder, IHostingEnvironment environment)
        {
            if (environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                var cert = GetSigningCertificate();

                if (cert == null)
                {
                    throw new Exception("Unable to retrieve identity server token signing cert");
                }

                builder.AddSigningCredential(cert);
            }

            return builder;
        }

        private static X509Certificate2 GetSigningCertificate()
        {
            using (var client = new AmazonSimpleSystemsManagementClient(Amazon.RegionEndpoint.EUWest1))
            {
                var cert = client.GetParameterAsync(new GetParameterRequest { Name = "MoneteerIdentityTokenSigningCert" }).Result;
                var secret = client.GetParameterAsync(new GetParameterRequest { Name = "MoneteerIdentityTokenSigningCertSecret", WithDecryption = true }).Result;

                // Decode the certificate
                var base64EncodedCert = cert.Parameter?.Value;
                var certificatePassword = secret.Parameter?.Value;
                byte[] decodedPfxBytes = Convert.FromBase64String(base64EncodedCert);
                return new X509Certificate2(decodedPfxBytes, certificatePassword);
            }
        }
    }
}
