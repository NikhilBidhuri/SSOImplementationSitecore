We have four folder for diffrent identity providers it consist all files required to implement SSO
OwinIntergration.config is common, replace the Processor name.
For sitecore 9.1 and after, Sitecore has identity server instance too
This code can be implemented on CM/CD not for Sitecore Identity Server
Dont forget to disable Sitecore Identity Server 
steps:
Sitecore provides the config to disable this in \App_Config\Include\Examples
Copy the file Sitecore.Owin.Authentication.IdentityServer.Disabler.config.example from \App_Config\Include\Examples\ into \App_Config\Environment\
Rename the file to .config



Thats all
Happy Coding!
LinkedIn : https://www.linkedin.com/in/nikhilbidhuri21/