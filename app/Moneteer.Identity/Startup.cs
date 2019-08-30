using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moneteer.Identity.Domain;
using Moneteer.Identity.Domain.Entities;
using Moneteer.Identity.Helpers;
using Moneteer.Identity.Repositories;
using Serilog;

namespace Moneteer.Identity
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IHostingEnvironment hostingEnvironment)
        {
            Configuration = configuration;
            Environment = hostingEnvironment;
        }

        public IHostingEnvironment Environment { get; }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                // This is disabled because it's only used on the landing page
                options.CheckConsentNeeded = context => false;
            });

            var moneteerConnectionString = Configuration.GetConnectionString("Moneteer");

            services.AddDbContext<DataProtectionKeysContext>(options => options.UseNpgsql(moneteerConnectionString));
            services.AddDbContext<Domain.IdentityDbContext>(options => options.UseNpgsql(moneteerConnectionString));
            services.AddDbContext<PersistedGrantContext>(options => options.UseNpgsql(moneteerConnectionString));
            services.AddIdentity<User, Role>(options => options.SignIn.RequireConfirmedEmail = true)
                    .AddDefaultTokenProviders()
                    .AddEntityFrameworkStores<Domain.IdentityDbContext>();

            // Data Protection - Provides storage and encryption for anti-forgery tokens
            if (Environment.IsDevelopment())
            {
                services.AddDataProtection()
                        .PersistKeysToDbContext<DataProtectionKeysContext>();
            }
            else 
            {
                services.AddDataProtection()
                        .PersistKeysToDbContext<DataProtectionKeysContext>()
                        .ProtectKeysWithCertificate(GetSigningCertificate());
            }

            services.AddAntiforgery();
            services.AddCors(options =>
            {
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins(Configuration["AllowedCorsOrigins"])
                          .AllowAnyHeader()
                          .AllowAnyMethod();
                });
            });

            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.AllowedForNewUsers = false;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

                options.SignIn.RequireConfirmedEmail = true;
                options.SignIn.RequireConfirmedPhoneNumber = false;
            });

            var publicOriginSetting = Configuration["PublicOrigin"];

            var identityBuilder = services.AddIdentityServer(options =>
            {
                if (!string.IsNullOrEmpty(publicOriginSetting))
                {
                    options.PublicOrigin = publicOriginSetting;
                }
            })
                .AddOperationalStore(options => 
                {
                    options.ConfigureDbContext = b => b.UseNpgsql(moneteerConnectionString);
                    options.EnableTokenCleanup = true;
                })
                .AddInMemoryIdentityResources(IdentityConfig.IdentityResources)
                .AddInMemoryClients(Configuration.GetSection("IdentityServer:Clients"))
                .AddInMemoryApiResources(IdentityConfig.GetApiResources(Configuration))
                .AddPersistedGrantStore<CustomPersistedGrantStore>()
                .AddAspNetIdentity<User>();

            if (Environment.IsDevelopment()) 
            {
                identityBuilder.AddDeveloperSigningCredential();
            } else 
            {
                identityBuilder.AddSigningCredential(GetSigningCertificate());
            }

            services.AddMvc(options => 
            {
                options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
            }).SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                options.KnownNetworks.Clear();
                options.KnownProxies.Clear();
            });

            services.AddSingleton<IConfigurationHelper, ConfigurationHelper>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseSerilogRequestLogging();
            app.UseForwardedHeaders();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseCors("default");
            app.UseStaticFiles();
            app.UseCookiePolicy();
            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();
        }

        private X509Certificate2 GetSigningCertificate()
        {
            var cert = Configuration["TokenSigningCert"];
            var secret = Configuration["TokenSigningCertSecret"];
                
            byte[] decodedPfxBytes = Convert.FromBase64String(cert);
            return new X509Certificate2(decodedPfxBytes, secret);
        }
    }
}
