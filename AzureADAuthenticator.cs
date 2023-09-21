using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OWINAuthentication.IdentityProviders
{
    // Azure AD Authentication
    public class AzureADAuthentication : IdentityProvidersProcessor
    {
        public AzureADAuthentication(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        // Identity provider name. Must match the configuration.
        protected override string IdentityProviderName
        {
            get { return "AzureAD"; }
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();
            string authenticationType = this.GetAuthenticationType();

            // Configure the Azure AD authentication options
            var azureAdOptions = new OpenIdConnectAuthenticationOptions
            {
                ClientId = "YourAzureADClientId",
                Authority = "https://login.microsoftonline.com/YourAzureADTenantId",
                RedirectUri = "YourRedirectUri",
                PostLogoutRedirectUri = "YourPostLogoutRedirectUri",
                AuthenticationType = authenticationType,
                Scope = "openid profile email",
                ResponseType = "id_token",
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false, // Set this based on your Azure AD configuration.
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = (context) =>
                    {
                        // Transform claims if needed
                        ClaimsIdentity identity = context.AuthenticationTicket.Identity;
                        foreach (Transformation current in identityProvider.Transformations)
                        {
                            current.Transform(identity, new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                        }
                        return Task.FromResult(0);
                    },
                    RedirectToIdentityProvider = (context) =>
                    {
                        // Handle any additional logic before redirecting to Azure AD, if required.
                        return Task.FromResult(0);
                    }
                }
            };

            // Register the Azure AD authentication with OWIN
            args.App.UseOpenIdConnectAuthentication(azureAdOptions);
        }
    }
}
