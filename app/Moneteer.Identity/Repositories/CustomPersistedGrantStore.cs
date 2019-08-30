using System.Diagnostics;
using IdentityServer4.EntityFramework.Interfaces;
using IdentityServer4.EntityFramework.Stores;
using Microsoft.Extensions.Logging;

namespace Moneteer.Identity.Repositories
{
    public class CustomPersistedGrantStore : PersistedGrantStore
    {
        public CustomPersistedGrantStore(PersistedGrantContext context, ILogger<PersistedGrantStore> logger) : base(context, logger)
        {
        }
    }
}