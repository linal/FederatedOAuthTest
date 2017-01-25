using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(FederatedLogin.Startup))]
namespace FederatedLogin
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
