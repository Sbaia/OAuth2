using FluentAssertions;
using NSubstitute;
using NUnit.Framework;
using OAuth2.Client;
using OAuth2.Client.Impl;
using OAuth2.Configuration;
using OAuth2.Infrastructure;
using OAuth2.Models;

namespace OAuth2.Tests.Client.Impl
{
    [TestFixture]
    public class AzureClientTests
    {
        private const string Content = @"
{
    ""@odata.context"": ""https://graph.microsoft.com/v1.0/$metadata#users/$entity"",
        ""id"": ""48d31887-5fad-4d73-a9f5-3c356e68a038"",
        ""businessPhones"": [
        ""+1 412 555 0109""
        ],
        ""displayName"": ""Megan Bowen"",
        ""givenName"": ""Megan"",
        ""jobTitle"": ""Auditor"",
        ""mail"": ""MeganB@M365x214355.onmicrosoft.com"",
        ""mobilePhone"": null,
        ""officeLocation"": ""12/1110"",
        ""preferredLanguage"": ""en-US"",
        ""surname"": ""Bowen"",
        ""userPrincipalName"": ""MeganB@M365x214355.onmicrosoft.com""
    }";
        private const string Tenant = "common";

        private AzureClientDescendant _descendant;
        private IRequestFactory _factory;

        [SetUp]
        public void SetUp()
        {
            _factory = Substitute.For<IRequestFactory>();
            _descendant = new AzureClientDescendant(
                _factory, Substitute.For<IClientConfiguration>());
        }

        [Test]
        public void Should_ReturnCorrectAccessCodeServiceEndpoint()
        {
            // act
            var endpoint = _descendant.GetAccessCodeServiceEndpoint();

            // assert
            endpoint.BaseUri.Should().Be("https://login.microsoftonline.com");
            endpoint.Resource.Should().Be($"/{Tenant}/oauth2/v2.0/authorize");
        }

        [Test]
        public void Should_ReturnCorrectAccessTokenServiceEndpoint()
        {
            // act
            var endpoint = _descendant.GetAccessTokenServiceEndpoint();

            // assert
            endpoint.BaseUri.Should().Be("https://login.microsoftonline.com");
            endpoint.Resource.Should().Be($"/{Tenant}/oauth2/v2.0/token");
        }

        [Test]
        public void Should_ReturnCorrectUserInfoServiceEndpoint()
        {
            // act
            var endpoint = _descendant.GetUserInfoServiceEndpoint();
            
            endpoint.BaseUri.Should().Be("https://graph.microsoft.com/v1.0");
            endpoint.Resource.Should().Be("/me");
        }

        [Test]
        public void Should_ParseAllFieldsOfUserInfo_WhenCorrectContentIsPassed()
        {
            // act
            var info = _descendant.ParseUserInfo(Content);

            //  assert
            info.Id.Should().Be("48d31887-5fad-4d73-a9f5-3c356e68a038");
            info.FirstName.Should().Be("Megan");
            info.LastName.Should().Be("Bowen");
            info.Email.Should().Be("MeganB@M365x214355.onmicrosoft.com");
            info.PhotoUri.Should().Be("https://graph.microsoft.com/beta/users/48d31887-5fad-4d73-a9f5-3c356e68a038/photos/96x96");
        }

        private class AzureClientDescendant : AzureClient
        {
            public AzureClientDescendant(IRequestFactory factory, IClientConfiguration configuration)
                : base(factory, configuration)
            {
            }

            public Endpoint GetAccessCodeServiceEndpoint()
            {
                return AccessCodeServiceEndpoint;
            }

            public Endpoint GetAccessTokenServiceEndpoint()
            {
                return AccessTokenServiceEndpoint;
            }

            public Endpoint GetUserInfoServiceEndpoint()
            {
                return UserInfoServiceEndpoint;
            }

            public new UserInfo ParseUserInfo(string content)
            {
                return base.ParseUserInfo(content);
            }
        }
    }
}