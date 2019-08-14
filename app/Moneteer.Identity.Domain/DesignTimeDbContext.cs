using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Moneteer.Identity.Domain
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<IdentityDbContext>
    {
        public IdentityDbContext CreateDbContext(string[] args)
        {
            foreach (var arg in args)
            {
                System.Console.WriteLine(arg);
            }
            
            var optionsBuilder = new DbContextOptionsBuilder<IdentityDbContext>();
            optionsBuilder.UseNpgsql("Server=127.0.0.1;User Id=postgres;Password=admin;Enlist=true;Database=moneteer;");

            return new IdentityDbContext(optionsBuilder.Options);
        }
    }
}
