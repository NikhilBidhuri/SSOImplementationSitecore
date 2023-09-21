using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System.Security.Claims;
using System.Web;

namespace OWINAuthentication.IdentityProviders
{
    //Facebook Authentication
    public class FacebookAuthentication : IdentityProvidersProcessor
    {
        public FacebookAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        /// <summary>
        /// Identityprovidr name. Has to match the configuration
        /// </summary>
        protected override string IdentityProviderName
        {
            get { return "Facebook"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            var facebookProvider = new FacebookAuthenticationProvider()
            {
                OnAuthenticated = (context) =>
                {
                    // transform all claims
                    ClaimsIdentity identity = context.Identity;
                    foreach (Transformation current in identityProvider.Transformations)
                    {
                        current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                    }
                    return System.Threading.Tasks.Task.FromResult(0);
                },

                OnReturnEndpoint = (context) =>
                {
                    if (context.Request.Query["state"] != null)
                    {
                        var state = HttpUtility.ParseQueryString(context.Request.Query["state"]);
                        //todo: do something with it.
                    }

                    return System.Threading.Tasks.Task.FromResult(0);
                }
            };

            FacebookAuthenticationOptions options = new FacebookAuthenticationOptions();
            options.AppId = "<APP-ID-HERE>";
            options.AppSecret = "<APP-SECERT-HERE>";
            options.Provider = facebookProvider;
            options.CallbackPath = new PathString("/signin-facebook");
            options.Fields.Add("name");
            options.Fields.Add("email");
            options.Scope.Add("email");
            args.App.UseFacebookAuthentication(options);

        }
    }
}