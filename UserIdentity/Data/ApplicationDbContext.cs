using UserIdentity.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;

namespace UserIdentity.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, Role, Guid, 
        UserClaim, UserRole, UserLogin, RoleClaim, UserToken>, IApplicationDbContext
    {

        private string _connectionString = "Data Source=DESKTOP-P9CGSEP\\SQLEXPRESS;Database=Identity;Trusted_Connection=True;";

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {

        }

        protected override void OnConfiguring(DbContextOptionsBuilder dbContextOptionsBuilder)
        {
            if (!dbContextOptionsBuilder.IsConfigured)
            {

                dbContextOptionsBuilder.UseSqlServer(_connectionString);
            }

            base.OnConfiguring(dbContextOptionsBuilder);
        }

        

    }
}
