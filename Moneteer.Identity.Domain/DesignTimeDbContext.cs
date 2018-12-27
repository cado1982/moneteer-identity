using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Moneteer.Identity.Domain
{
    public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
            optionsBuilder.UseSqlServer("data source=(localdb)\\MSSQLLocalDB;initial catalog=Moneteer;integrated security=SSPI");

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
