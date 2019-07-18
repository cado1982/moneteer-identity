using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Moneteer.Identity.Domain
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            foreach (var bleh in args)
            {
                System.Console.WriteLine(bleh);
            }
            
            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
            optionsBuilder.UseNpgsql("Server=127.0.0.1;User Id=postgres;Password=admin;Enlist=true;Database=moneteer-identity;");

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
