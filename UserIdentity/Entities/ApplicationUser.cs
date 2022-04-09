using Microsoft.AspNetCore.Identity;
using System;

namespace UserIdentity.Entities
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string Address { get; set; }
        public string Education { get; set; }
    }
}
