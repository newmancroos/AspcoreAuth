using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace _2.IdentitySample.Data
{
    public class AppDbContext : IdentityDbContext 
        // Since we use Identity we need to use IdentityDbContext instead of  DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }
    }
}
