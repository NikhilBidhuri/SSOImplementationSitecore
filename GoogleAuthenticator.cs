using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;

namespace OWINAuthentication.IdentityProviders
{
    // Google Authentication
    public class GoogleAuthentication : IdentityProvidersProcessor
    {
        public GoogleAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        // Identity provider name. Must match the configuration.
        protected override string IdentityProviderName
        {
            get { return "Google"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            var googleProvider = new GoogleOAuth2AuthenticationProvider()
            {
                OnAuthenticated = (context) =>
                {
                    // Transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            GoogleOAuth2AuthenticationOptions options = new GoogleOAuth2AuthenticationOptions
            {
                ClientId = "YourGoogleClientId",
                ClientSecret = "YourGoogleClientSecret",
                CallbackPath = new PathString("/signin-google"),
                Provider = googleProvider
            };

            args.App.UseGoogleAuthentication(options);
        }
    }
}
