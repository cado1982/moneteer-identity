using System.Threading.Tasks;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.EntityFramework.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace Moneteer.Identity.Repositories
{
    public class PersistedGrantContext : DbContext, IPersistedGrantDbContext
    {
        public PersistedGrantContext(DbContextOptions<PersistedGrantContext> options) 
            : base(options) { }

        public DbSet<PersistedGrant> PersistedGrants { get; set; }
        public DbSet<DeviceFlowCodes> DeviceFlowCodes { get; set; }

        public Task<int> SaveChangesAsync()
        {
            return base.SaveChangesAsync();
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PersistedGrant>(b =>
            {
                b.ToTable("persisted_grants", "identity")
                    .HasKey(p => p.Key);
                b.Property(p => p.ClientId).HasColumnName("client_id");
                b.Property(p => p.CreationTime).HasColumnName("creation_time");
                b.Property(p => p.Data).HasColumnName("data");
                b.Property(p => p.Expiration).HasColumnName("expiration");
                b.Property(p => p.Key).HasColumnName("key");
                b.Property(p => p.SubjectId).HasColumnName("subject_id");
                b.Property(p => p.Type).HasColumnName("type");
            });

            builder.Entity<DeviceFlowCodes>(b =>
            {
                b.ToTable("device_codes", "identity")
                    .HasKey(p => p.UserCode);
                b.Property(p => p.ClientId).HasColumnName("client_id");
                b.Property(p => p.CreationTime).HasColumnName("creation_time");
                b.Property(p => p.Data).HasColumnName("data");
                b.Property(p => p.Expiration).HasColumnName("expiration");
                b.Property(p => p.DeviceCode).HasColumnName("device_code");
                b.Property(p => p.SubjectId).HasColumnName("subject_id");
                b.Property(p => p.UserCode).HasColumnName("user_code");
            });
        }
    }
}