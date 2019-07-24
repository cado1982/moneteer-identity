using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Moneteer.Identity.Domain;
using Moneteer.Identity.Extensions;
using Moneteer.Identity.Helpers;

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

            var identityConnectionString = Configuration.GetConnectionString("Identity");

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseNpgsql(identityConnectionString, x =>
                {
                    x.MigrationsAssembly("Moneteer.Identity.Domain");
                }));
            services.AddIdentity<IdentityUser, IdentityRole>(options => options.SignIn.RequireConfirmedEmail = true)
                    .AddDefaultTokenProviders()
                    .AddEntityFrameworkStores<ApplicationDbContext>();

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

            services.AddIdentityServer(options =>
            {
                if (!string.IsNullOrEmpty(publicOriginSetting))
                {
                    options.PublicOrigin = publicOriginSetting;
                }
            })
                .LoadSigningCredential(Environment, Configuration)
                .AddInMemoryIdentityResources(Config.IdentityResources)
                .AddInMemoryClients(Configuration.GetSection("IdentityServer:Clients"))
                .AddInMemoryApiResources(Config.Apis)
                .AddAspNetIdentity<IdentityUser>();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.All;
            });

            services.AddSingleton<IConfigurationHelper, ConfigurationHelper>();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ApplicationDbContext dbContext)
        {
            dbContext.Database.Migrate();
            
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
    }
}
