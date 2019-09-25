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

            var trialExpiryTimestamp = (int)user.TrialExpiry.Subtract(new System.DateTime(1970,1,1)).TotalSeconds;
            _logger.LogDebug($"Adding trialExpiry claim for user {sub} with value {trialExpiryTimestamp}");
            claims.Add(new Claim(CustomClaimTypes.TrialExpiry, trialExpiryTimestamp.ToString(), ClaimValueTypes.Integer32));
            
            if (user.SubscriptionExpiry.HasValue) 
            {
                var subscriptionExpiryTimestamp = (int)user.SubscriptionExpiry.Value.Subtract(new System.DateTime(1970,1,1)).TotalSeconds;
                _logger.LogDebug($"Adding subscriptionExpiry claim for user {sub} with value {subscriptionExpiryTimestamp}");
                claims.Add(new Claim(CustomClaimTypes.SubscriptionExpiry, subscriptionExpiryTimestamp.ToString()));
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