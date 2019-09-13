using System;
using Microsoft.AspNetCore.Identity;

namespace Moneteer.Identity.Domain.Entities
{
    public class User: IdentityUser<Guid>
    {   
        public DateTime TrialExpiry { get; set; }
        public DateTime? SubscriptionExpiry { get; set; }
        public string StripeId { get; set; }
    }
}