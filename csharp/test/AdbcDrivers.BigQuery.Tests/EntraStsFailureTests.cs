/*
* Copyright (c) 2026 ADBC Drivers Contributors
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Apache.Arrow.Adbc;
using Xunit;

namespace AdbcDrivers.BigQuery.Tests
{
    /// <summary>
    /// Tests for the diagnostics surfaced when the Google Security Token Service rejects a
    /// Microsoft Entra ID token during the "aad" federation flow.
    /// </summary>
    public class EntraStsFailureTests
    {
        private static string ExchangeFailure(string body, HttpStatusCode statusCode = HttpStatusCode.BadRequest)
        {
            using HttpClient httpClient = new HttpClient(new StubHandler(body, statusCode));
            using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, "https://sts.googleapis.com/v1/token")
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            };

            AdbcException exception = Assert.Throws<AdbcException>(() =>
                WorkloadIdentityFederation.SendAsync(
                    httpClient, request, WorkloadIdentityFederation.StsExchangeStep,
                    "The Google Security Token Service", null, default).GetAwaiter().GetResult());

            return exception.Message;
        }

        [Fact]
        public void StsFailureNamesTheEndpointStatusAndStep()
        {
            string message = ExchangeFailure("{\"error\":\"invalid_request\"}");

            Assert.Contains("Security Token Service", message);
            Assert.Contains("400", message);
            Assert.Contains(WorkloadIdentityFederation.StsExchangeStep, message);
            Assert.Contains("invalid_request", message);
        }

        /// <summary>
        /// Regression guard for the real failure seen when a provider mapped google.subject to
        /// assertion.oid but the connector federated an Entra id_token, which had no oid claim.
        /// The remediation is only discoverable from the response body.
        /// </summary>
        [Fact]
        public void StsFailureSurfacesUnmappedSubjectReason()
        {
            string message = ExchangeFailure(
                "{\"error\":\"unauthorized_client\",\"error_description\":\"Could not obtain a value for google.subject from the given credential.\"}");

            Assert.Contains("google.subject", message);
            Assert.Contains("unauthorized_client", message);
        }

        [Fact]
        public void StsFailureFallsBackToTheRawBodyWhenItIsNotJson()
        {
            string message = ExchangeFailure("<html>502 from a proxy</html>", HttpStatusCode.BadGateway);

            Assert.Contains("502", message);
            Assert.Contains("proxy", message);
        }

        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly string body;
            private readonly HttpStatusCode statusCode;

            public StubHandler(string body, HttpStatusCode statusCode)
            {
                this.body = body;
                this.statusCode = statusCode;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return Task.FromResult(new HttpResponseMessage(this.statusCode)
                {
                    Content = new StringContent(this.body, Encoding.UTF8, "application/json")
                });
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void StsFailureStillReportsStatusWhenTheBodyIsEmpty(string body)
        {
            string message = ExchangeFailure(body, HttpStatusCode.Forbidden);

            Assert.Contains("403", message);
            Assert.Contains(WorkloadIdentityFederation.StsExchangeStep, message);
        }

        [Fact]
        public void TokenFailureMessageIncludesStatusCodeAndResponseBody()
        {
            const string body = "{\"error\":\"invalid_grant\"}";

            string message = BigQueryConnection.BuildTokenFailureMessage(HttpStatusCode.Unauthorized, body);

            Assert.Contains("401", message);
            Assert.Contains("Unauthorized", message);
            Assert.Contains(body, message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void TokenFailureMessageHandlesMissingResponseBody(string? body)
        {
            string message = BigQueryConnection.BuildTokenFailureMessage(HttpStatusCode.BadGateway, body);

            Assert.Contains("502", message);
            Assert.Contains("no response body", message);
        }

        /// <summary>
        /// The connector federates an Entra *access* token, so the subject token type must be the
        /// generic JWT type. Declaring it as an id_token misrepresents the credential to the
        /// Security Token Service.
        /// </summary>
        [Fact]
        public void StsRequestBodyDeclaresAccessTokenAsJwt()
        {
            string body = BigQueryConnection.CreateEntraStsRequestBody(WorkloadAudience, "an.entra.accesstoken");

            Assert.Contains(BigQueryConstants.AzureSubjectTokenType, body);
            // The connector federates an access token, so the id_token type must not reappear.
            Assert.DoesNotContain("urn:ietf:params:oauth:token-type:id_token", body);
        }

        private const string WorkloadAudience =
            "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/pool/providers/entra";

        /// <summary>
        /// options.userProject is a workforce pool concept. This connector federates through workload
        /// identity pools, whose audience already names the project, so the request must not carry it.
        /// </summary>
        [Fact]
        public void StsRequestBodyDoesNotCarryUserProject()
        {
            string body = BigQueryConnection.CreateEntraStsRequestBody(WorkloadAudience, "an.entra.accesstoken");

            Assert.DoesNotContain("options", body);
            Assert.DoesNotContain("userProject", body);
        }

        private const string WorkforceAudience =
            "//iam.googleapis.com/locations/global/workforcePools/pool/providers/sso";

        /// <summary>
        /// Workforce pools federate users, whose tokens are not bound to a project, so the exchange
        /// names the quota and billing project in options.userProject, as a serialized JSON object.
        /// </summary>
        [Fact]
        public void WorkforceStsRequestBodyCarriesUserProject()
        {
            string body = BigQueryConnection.CreateEntraStsRequestBody(
                WorkforceAudience, "an.idp.token", BigQueryConstants.AzureSubjectTokenType, "my-project");

            using JsonDocument document = JsonDocument.Parse(body);
            string options = document.RootElement.GetProperty("options").GetString()!;
            using JsonDocument optionsDocument = JsonDocument.Parse(options);
            Assert.Equal("my-project", optionsDocument.RootElement.GetProperty("userProject").GetString());
        }

        [Fact]
        public void WorkloadStsRequestBodyIgnoresUserProject()
        {
            string body = BigQueryConnection.CreateEntraStsRequestBody(
                WorkloadAudience, "an.entra.accesstoken", BigQueryConstants.AzureSubjectTokenType, "my-project");

            Assert.DoesNotContain("userProject", body);
        }

        [Theory]
        [InlineData(null, null, "my-project", "my-project")]
        [InlineData(null, "billing-project", "my-project", "billing-project")]
        [InlineData("quota-project", "billing-project", "my-project", "quota-project")]
        [InlineData(null, null, BigQueryConstants.DetectProjectId, null)]
        public void WorkforceUserProjectFallsBackToBillingThenProject(string? userProject, string? billingProject, string projectId, string? expected)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.WorkforceAuthenticationType,
                [BigQueryParameters.ProjectId] = projectId,
            };
            if (userProject != null) properties[BigQueryParameters.WorkforcePoolUserProject] = userProject;
            if (billingProject != null) properties[BigQueryParameters.BillingProjectId] = billingProject;

            using BigQueryConnection connection = new BigQueryConnection(properties);

            Assert.Equal(expected, connection.GetWorkforcePoolUserProject(WorkforceAudience));
            Assert.Null(connection.GetWorkforcePoolUserProject(WorkloadAudience));
        }

        [Theory]
        [InlineData(null, "urn:ietf:params:oauth:token-type:id_token")]
        [InlineData("jwt", "urn:ietf:params:oauth:token-type:jwt")]
        [InlineData("ID_TOKEN", "urn:ietf:params:oauth:token-type:id_token")]
        [InlineData("saml2", "urn:ietf:params:oauth:token-type:saml2")]
        [InlineData("urn:ietf:params:oauth:token-type:id_token", "urn:ietf:params:oauth:token-type:id_token")]
        public void SubjectTokenTypeIsResolvedToItsUrn(string? configured, string expected)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.WorkforceAuthenticationType,
            };
            if (configured != null) properties[BigQueryParameters.SubjectTokenType] = configured;

            using BigQueryConnection connection = new BigQueryConnection(properties);

            Assert.Equal(expected, connection.GetSubjectTokenType());
        }

        [Fact]
        public void UnknownSubjectTokenTypeIsRejected()
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.WorkforceAuthenticationType,
                [BigQueryParameters.SubjectTokenType] = "access_token",
            };

            using BigQueryConnection connection = new BigQueryConnection(properties);

            Assert.Throws<ArgumentException>(() => connection.GetSubjectTokenType());
        }

        /// <summary>
        /// accounts.google.com does not exist outside googleapis.com, so user authentication must
        /// point to workforce identity federation instead of failing at the token endpoint.
        /// </summary>
        [Fact]
        public void UserAuthenticationOutsideTheDefaultUniversePointsToWorkforceFederation()
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.UserAuthenticationType,
                [BigQueryParameters.UniverseDomain] = "s3nsapis.fr",
                [BigQueryParameters.ClientId] = "client",
                [BigQueryParameters.ClientSecret] = "secret",
                [BigQueryParameters.RefreshToken] = "refresh",
            };

            using BigQueryConnection connection = new BigQueryConnection(properties);

            ArgumentException exception = Assert.Throws<ArgumentException>(() => connection.SetCredential());
            Assert.Contains($"`{BigQueryConstants.WorkforceAuthenticationType}`", exception.Message);
            Assert.Contains("workforcePools", exception.Message);
        }

        /// <summary>
        /// Workforce authentication signs users in, so a workload pool audience is a configuration
        /// mistake that is reported before any call to the Security Token Service.
        /// </summary>
        [Fact]
        public void WorkforceAuthenticationRequiresAWorkforcePoolAudience()
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.WorkforceAuthenticationType,
                [BigQueryParameters.AccessToken] = "an.idp.token",
                [BigQueryParameters.AudienceUri] = WorkloadAudience,
            };

            using BigQueryConnection connection = new BigQueryConnection(properties);

            ArgumentException exception = Assert.Throws<ArgumentException>(() => connection.SetCredential());
            Assert.Contains(BigQueryParameters.AudienceUri, exception.Message);
        }

        [Theory]
        [InlineData(BigQueryParameters.AccessToken)]
        [InlineData(BigQueryParameters.AudienceUri)]
        public void WorkforceAuthenticationRequiresTokenAndAudience(string missing)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>
            {
                [BigQueryParameters.AuthenticationType] = BigQueryConstants.WorkforceAuthenticationType,
                [BigQueryParameters.AccessToken] = "an.idp.token",
                [BigQueryParameters.AudienceUri] = WorkforceAudience,
            };
            properties.Remove(missing);

            using BigQueryConnection connection = new BigQueryConnection(properties);

            ArgumentException exception = Assert.Throws<ArgumentException>(() => connection.SetCredential());
            Assert.Contains(missing, exception.Message);
        }
    }
}
