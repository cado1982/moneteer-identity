using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Moneteer.Identity.Domain.Entities;
using Moneteer.Identity.Models;

namespace Moneteer.Identity.Services
{
    public class CustomProfileService : IProfileService
    {
        private readonly UserManager<User> _userManager;
        private readonly ILogger<CustomProfileService> _logger;
        private readonly IUserClaimsPrincipalFactory<User> _claimsFactory;


        public CustomProfileService(UserManager<User> userManager, ILogger<CustomProfileService> logger, IUserClaimsPrincipalFactory<User> claimsFactory)
        {
            _logger = logger;
            _userManager = userManager;
            _claimsFactory = claimsFactory;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            _logger.LogDebug("Entered GetProfileDataAsync");

            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            var principal = await _claimsFactory.CreateAsync(user);

            _logger.LogDebug($"Generating claims for user {sub}");

            var claims = principal.Claims.ToList();
            claims = claims.Where(c => context.RequestedClaimTypes.Contains(c.Type)).ToList();

            _logger.LogDebug($"Adding trialExpiry claim for user {sub} with value {user.TrialExpiry.ToString()}");
            claims.Add(new Claim(CustomClaimTypes.TrialExpiry, user.TrialExpiry.ToString()));

            if (user.SubscriptionExpiry != null) 
            {
                _logger.LogDebug($"Adding subscriptionExpiry claim for user {sub} with value {user.SubscriptionExpiry.ToString()}");
                claims.Add(new Claim(CustomClaimTypes.SubscriptionExpiry, user.SubscriptionExpiry.ToString()));
            }

            context.IssuedClaims = claims;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            _logger.LogDebug("Entered IsActiveAsync");

            return Task.CompletedTask;
        }
    }
}