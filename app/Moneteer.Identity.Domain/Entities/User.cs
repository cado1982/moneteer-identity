using System;
using Microsoft.AspNetCore.Identity;

namespace Moneteer.Identity.Domain.Entities
{
    public class User: IdentityUser<Guid>
    {   
        [PersonalData]
        public DateTime TrialExpiry { get; set; }

        [PersonalData]
        public DateTime? SubscriptionExpiry { get; set; }

        public string StripeId { get; set; }
    }
}