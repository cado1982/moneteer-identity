using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Moneteer.Identity.Domain
{
    public class ApplicationDbContext : IdentityDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<IdentityUser>()
                .Property(u => u.Id)
                .HasMaxLength(450);

            builder.Entity<IdentityRole>()
                .Property(r => r.Id)
                .HasMaxLength(450);

            // These properties are also used in keys
            builder.Entity<IdentityUserLogin<string>>()
                .Property(l => l.LoginProvider)
                .HasMaxLength(450);

            builder.Entity<IdentityUserLogin<string>>()
                .Property(l => l.ProviderKey)
                .HasMaxLength(450);

            builder.Entity<IdentityUserToken<string>>()
                .Property(t => t.LoginProvider)
                .HasMaxLength(450);

            builder.Entity<IdentityUserToken<string>>()
                .Property(t => t.Name)
                .HasMaxLength(450);
        }
    }
}
