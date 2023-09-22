using System;
using System.Security.Claims;
using Microsoft.Owin.Infrastructure;
using Owin;
using Sitecore.Abstractions;
using Sitecore.Configuration;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin;


namespace CodewithNikhil.Foundation.Authentication.Saml2
{
    public class Saml2IdentityProviderProcessor : IdentityProvidersProcessor
    {
        private readonly string _spEntityId;
        private readonly string _spReturnUrl;
        private readonly string _ipEntityId;
        private readonly string _ipMetadataLocation;

        public Saml2IdentityProviderProcessor(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration, ICookieManager cookieManager, BaseSettings settings) : base(federatedAuthenticationConfiguration, cookieManager, settings)
        {
            _spEntityId = Settings.GetSetting("SAML2.ServiceProvider.EntityId");
            _spReturnUrl = Settings.GetSetting("SAML2.ServiceProvider.ReturnUrl");
            _ipEntityId = Settings.GetSetting("SAML2.IdentityProvider.EntityId");
            _ipMetadataLocation = Settings.GetSetting("SAML2.IdentityProvider.MetadataLocation");
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            var options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = new SPOptions
                {
                    EntityId = new EntityId(_spEntityId),
                    ReturnUrl = new Uri(_spReturnUrl)
                },
                AuthenticationType = GetAuthenticationType()
            };

            options.IdentityProviders.Add(new Sustainsys.Saml2.IdentityProvider(new EntityId(_ipEntityId), options.SPOptions)
            {
                MetadataLocation = _ipMetadataLocation,
                LoadMetadata = true
            });

            options.Notifications = new Saml2Notifications
            {
                AcsCommandResultCreated = (result, response) =>
                {
                    var identityProvider = GetIdentityProvider();
                    ((ClaimsIdentity)result.Principal.Identity).ApplyClaimsTransformations(new TransformationContext(FederatedAuthenticationConfiguration, identityProvider));
                }
            };

            args.App.UseSaml2Authentication(options);
        }

        protected override string IdentityProviderName => "saml2";
    }
    public class KentorCookieSaver : InitializeProcessor
    {
        public override void Process(InitializeArgs args)
        {
            args.App.UseKentorOwinCookieSaver(PipelineStage.Authenticate);
        }
    }
}