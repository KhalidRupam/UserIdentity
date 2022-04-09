using System.Collections.Generic;
using UserIdentity.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace UserIdentity.Services
{
    public class RoleManager
        : RoleManager<Role>
    {
        public RoleManager(IRoleStore<Role> store, IEnumerable<IRoleValidator<Role>> roleValidators, ILookupNormalizer keyNormalizer, IdentityErrorDescriber errors, ILogger<RoleManager<Role>> logger)
            : base(store, roleValidators, keyNormalizer, errors, logger)
        {
        }
    }
}
  