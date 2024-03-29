﻿using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Moneteer.Identity.Domain.Entities;

namespace Moneteer.Identity.Domain
{
    public class IdentityDbContext : Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityDbContext<User, Role, Guid>
    {
        public IdentityDbContext(DbContextOptions<IdentityDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>(b =>
            {
                b.ToTable("users", "identity");
                b.Property(u => u.Id).HasColumnName("id");
                b.Property(u => u.UserName).HasColumnName("user_name");
                b.Property(u => u.NormalizedUserName).HasColumnName("normalized_user_name");
                b.Property(u => u.Email).HasColumnName("email");
                b.Property(u => u.NormalizedEmail).HasColumnName("normalized_email");
                b.Property(u => u.EmailConfirmed).HasColumnName("email_confirmed");
                b.Property(u => u.PasswordHash).HasColumnName("password_hash");
                b.Property(u => u.SecurityStamp).HasColumnName("security_stamp");
                b.Property(u => u.ConcurrencyStamp).HasColumnName("concurrency_stamp");
                b.Property(u => u.PhoneNumber).HasColumnName("phone_number");
                b.Property(u => u.PhoneNumberConfirmed).HasColumnName("phone_number_confirmed");
                b.Property(u => u.TwoFactorEnabled).HasColumnName("two_factor_enabled");
                b.Property(u => u.LockoutEnd).HasColumnName("lockout_end");
                b.Property(u => u.LockoutEnabled).HasColumnName("lockout_enabled");
                b.Property(u => u.AccessFailedCount).HasColumnName("access_failed_count");
                b.Property(e => e.SubscriptionExpiry).HasColumnName("subscription_expiry");
                b.Property(e => e.TrialExpiry).HasColumnName("trial_expiry");
                b.Property(e => e.StripeId).HasColumnName("stripe_id");
            });

            builder.Entity<IdentityUserToken<Guid>>(b =>
            {
                b.ToTable("user_tokens", "identity");
                //b.HasKey(k => new {k.UserId, k.Name, k.LoginProvider});
                b.Property(t => t.LoginProvider).HasColumnName("login_provider");
                b.Property(t => t.Name).HasColumnName("name");
                b.Property(t => t.UserId).HasColumnName("user_id");
                b.Property(t => t.Value).HasColumnName("value");
            });

            builder.Entity<IdentityUserClaim<Guid>>(b =>
            {
                b.ToTable("user_claims", "identity");
                //b.HasKey(k => k.Id);
                b.Property(p => p.Id).HasColumnName("id");
                b.Property(p => p.UserId).HasColumnName("user_id");
                b.Property(p => p.ClaimType).HasColumnName("claim_type");
                b.Property(p => p.ClaimValue).HasColumnName("claim_value");
            });

            builder.Entity<Role>(b => {
                b.ToTable("roles", "identity");
                b.Property(p => p.Id).HasColumnName("id");
                b.Property(p => p.Name).HasColumnName("name");
                b.Property(p => p.NormalizedName).HasColumnName("normalized_name");
                b.Property(p => p.ConcurrencyStamp).HasColumnName("concurrency_stamp");
            });

            builder.Entity<IdentityUserRole<Guid>>(b => {
                b.ToTable("user_roles", "identity");
                b.Property(p => p.UserId).HasColumnName("user_id");
                b.Property(p => p.RoleId).HasColumnName("role_id");
            });

            builder.Entity<IdentityRoleClaim<Guid>>(b => {
                b.ToTable("role_claims", "identity");
                b.Property(p => p.Id).HasColumnName("id");
                b.Property(p => p.RoleId).HasColumnName("role_id");
                b.Property(p => p.ClaimValue).HasColumnName("claim_value");
                b.Property(p => p.ClaimType).HasColumnName("claim_type");
            });

            builder.Entity<IdentityUserLogin<Guid>>(b => {
                b.ToTable("user_logins", "identity");
                b.Property(p => p.UserId).HasColumnName("user_id");
                b.Property(p => p.ProviderKey).HasColumnName("provider_key");
                b.Property(p => p.ProviderDisplayName).HasColumnName("provider_display_name");
                b.Property(p => p.LoginProvider).HasColumnName("login_provider");
            });
        }
    }
}
