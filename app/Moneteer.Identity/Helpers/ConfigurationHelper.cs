using Microsoft.Extensions.Configuration;

namespace Moneteer.Identity.Helpers
{
    public class ConfigurationHelper : IConfigurationHelper
    {
        private readonly IConfiguration _configuration;

        public ConfigurationHelper(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string LandingUri
        {
            get { return _configuration["LandingUri"]; }
        }

        public string AppUri
        {
            get { return _configuration["AppUri"]; }
        }
    }
}
