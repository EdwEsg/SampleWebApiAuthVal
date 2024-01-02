using Microsoft.EntityFrameworkCore;
using SampleWebApi.Domain;

namespace SampleWebApi.Data
{
    public class SampleWebApiDbContext : DbContext
    {
        public SampleWebApiDbContext(DbContextOptions<SampleWebApiDbContext> options) : base(options) { }
        
        public virtual DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder) { }
        
           
        

    }
}
