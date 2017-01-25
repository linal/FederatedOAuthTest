using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace FederatedLogin.Controllers
{
    public class TokenController : Controller
    {
        // GET: Token
        public ActionResult Get()
        {
            WSFederationMessage wsFederationMessage;
            if (!WSFederationMessage.TryCreateFromUri(HttpContext.Request.Url, out wsFederationMessage))
            {
                throw new SecurityException("Invalid Uri");
            }


            var config = new EmbeddedTokenServiceConfiguration();
            var sts = config.CreateSecurityTokenService();

            SignInRequestMessage signInRequestMessage = wsFederationMessage as SignInRequestMessage;
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(HttpContext.User);

            var signInResponseMessage =
                FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(signInRequestMessage,
                    claimsPrincipal, sts);

            return new ContentResult
            {
                Content = signInResponseMessage.WriteFormPost()
            };
        }

        public class EmbeddedTokenServiceConfiguration : SecurityTokenServiceConfiguration
        {
            public EmbeddedTokenServiceConfiguration()
                : base(false)
            {
                this.SecurityTokenService = typeof(EmbeddedTokenService);
                this.TokenIssuerName = "YourSTSName";
                this.SigningCredentials = new X509SigningCredentials(SigningCertificate);
                this.DefaultTokenLifetime = TimeSpan.FromMinutes(60 * 10);
            }


            internal const string SigningCertificateFile = "EmbeddedSigningCert.pfx";
            internal const string SigningCertificatePassword = "password";

            public static X509Certificate2 SigningCertificate
            {
                get
                {
                    return new X509Certificate2(AssetManager.LoadBytes(SigningCertificateFile), SigningCertificatePassword);
                }
            }

            class AssetManager
            {
                static readonly string Prefix = typeof(AssetManager).Namespace + ".";

                public static string LoadString(string file)
                {
                    return Encoding.UTF8.GetString(LoadBytes(file));
                }

                public static byte[] LoadBytes(string file)
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(Prefix + file))
                        {
                            s.CopyTo(ms);
                            return ms.ToArray();
                        }
                    }
                }
            }
        }

        public class EmbeddedTokenService : SecurityTokenService
        {
            private readonly SecurityTokenServiceConfiguration securityTokenServiceConfiguration;

            public EmbeddedTokenService(SecurityTokenServiceConfiguration securityTokenServiceConfiguration) : base(securityTokenServiceConfiguration)
            {
                this.securityTokenServiceConfiguration = securityTokenServiceConfiguration;
            }

            protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
            {
                var scope = new Scope(request.AppliesTo.Uri.AbsoluteUri,
                    securityTokenServiceConfiguration.SigningCredentials)
                {
                    TokenEncryptionRequired = false,
                    ReplyToAddress = request.AppliesTo.Uri.AbsoluteUri
                };

                return scope;
            }

            protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
            {
                return (ClaimsIdentity) principal.Identity;
            }
        }
    }
}