using Microsoft.Owin;
using Microsoft.Owin.Security.Twitter;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;

namespace OWINAuthentication.IdentityProviders
{
    // Twitter Authentication
    public class TwitterAuthentication : IdentityProvidersProcessor
    {
        public TwitterAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        /// <summary>
        /// Identity provider name. Must match the configuration.
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Twitter"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            var twitterProvider = new TwitterAuthenticationProvider()
            {
                OnAuthenticated = (context) =>
                {
                    // Transform claims as needed
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            TwitterAuthenticationOptions options = new TwitterAuthenticationOptions();
            options.ConsumerKey = "YourTwitterConsumerKey";
            options.ConsumerSecret = "YourTwitterConsumerSecret";
            options.Provider = twitterProvider;

            args.App.UseTwitterAuthentication(options);
        }
    }
}
