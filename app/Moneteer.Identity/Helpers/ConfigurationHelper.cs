using Microsoft.Extensions.Configuration;

public class ConfigurationHelper : IConfigurationHelper
{
    private readonly IConfiguration _configuration;

    public ConfigurationHelper(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public string LandingPageUri
    {
        get { return _configuration["LandingPageUri"]; }
    }

    public string AppUri
    {
        get { return _configuration["AppUri"]; }
    }
}