using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;
using RestSharp.Authenticators;

namespace OAuth2.Client.Impl
{
    public class AzureClient : OAuth2Client
    {
        public AzureClient(IRequestFactory factory, IClientConfiguration configuration) : base(factory, configuration)
        {
            // CodeVerifier = CreateCodeVerifier();
            Nonce = CreateCodeVerifier(64);
        }

        private string Nonce { get; }
        // private string CodeVerifier { get; }
        public override string Name => "Azure";

        public string Tenant { get; set; } = "common";
        
        /// <summary>
        /// Defines URI of service which issues access code.
        /// </summary>
        protected override Endpoint AccessCodeServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://login.microsoftonline.com",
                    Resource = $"/{Tenant}/oauth2/v2.0/authorize"
                };
            }
        }

        // https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=6731de76-14a6-49ae-97bc-6eba6914391e&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fmyapp%2F&response_mode=query&scope=openid%20offline_access%20https%3A%2F%2Fgraph.microsoft.com%2Fmail.read&state=12345
        /// <summary>
        /// Defines URI of service which issues access token.
        /// </summary>
        protected override Endpoint AccessTokenServiceEndpoint
        {
            get
            {
                return new Endpoint
                {
                    BaseUri = "https://login.microsoftonline.com",
                    Resource = $"/{Tenant}/oauth2/v2.0/token"
                };
            }
        }

        /// <summary>
        /// Defines URI of service which allows to obtain information about user which is currently logged in.
        /// </summary>
        protected override Endpoint UserInfoServiceEndpoint
        {
            get
            {
                //TODO:
                return new Endpoint
                {
                    BaseUri = "https://graph.microsoft.com/beta",
                    Resource = $"/me"
                };
            }
        }


        public override Task<string> GetLoginLinkUriAsync(string state = null,
            CancellationToken cancellationToken = default, NameValueCollection queryParameters = null)
        {
            if (queryParameters == null)
                queryParameters = new NameValueCollection();
            // queryParameters.Add("resource", "https://graph.microsoft.com");
            return base.GetLoginLinkUriAsync(state, cancellationToken, queryParameters);
        }
        /// <summary>
        /// Called just before issuing request to third-party service when everything is ready.
        /// Allows to add extra parameters to request or do any other needed preparations.
        /// </summary>
        protected override void BeforeGetUserInfo(BeforeAfterRequestArgs args)
        {
            args.Client.Authenticator = new OAuth2AuthorizationRequestHeaderAuthenticator(AccessToken, "Bearer");
        }

        protected override void BeforeGetAccessToken(BeforeAfterRequestArgs args)
        {
            base.BeforeGetAccessToken(args);
            // args.Request.AddParameter("state", "12225890");
            // args.Request.AddParameter("resource", "https://outlook.office365.com");
        }

        private string CreateCodeVerifier(int size = 32)
        {
            var buffer = new byte[32];

            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(buffer);

            var verifier = Convert.ToBase64String(buffer)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
            return verifier;
        }

        private string CreateCodeChallenge(string verifier)
        {
            var sha = new SHA256Managed();
            sha.ComputeHash(Encoding.UTF8.GetBytes(verifier));

            string challenge = Convert.ToBase64String(sha.Hash)
                .Replace('+', '-')
                .Replace('/', '_')
                .Replace("=", "");
            return challenge;
        }

        protected override UserInfo ParseUserInfo(string content)
        {
            var response = JObject.Parse(content);
            const string avatarUri = "https://graph.microsoft.com/beta/users/{0}/photos/{1}";
            var userId = response["id"].Value<string>();
            return new UserInfo
            {
                Id = userId,
                Email = response["mail"].SafeGet(x => x.Value<string>()),
                FirstName = response["givenName"].Value<string>(),
                LastName = response["surname"].Value<string>(),
                ProviderName = this.Name,
                AvatarUri =
                {
                    Small = string.Format(avatarUri, userId, "48x48"),
                    Normal = string.Format(avatarUri, userId, "96x96"),
                    Large = string.Format(avatarUri, userId, "240x240"),
                }
            };
        }
    }
}
