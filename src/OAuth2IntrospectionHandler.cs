// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Authentication handler for OAuth 2.0 introspection
    /// </summary>
    public class OAuth2IntrospectionHandler : AuthenticationHandler<OAuth2IntrospectionOptions>
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<OAuth2IntrospectionHandler> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2IntrospectionHandler"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="urlEncoder">The URL encoder.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="cache">The cache.</param>
        public OAuth2IntrospectionHandler(
            IOptionsMonitor<OAuth2IntrospectionOptions> options,
            UrlEncoder urlEncoder,
            ISystemClock clock,
            ILoggerFactory loggerFactory,
            IDistributedCache cache = null)
            : base(options, loggerFactory, urlEncoder, clock)
        {
            _logger = loggerFactory.CreateLogger<OAuth2IntrospectionHandler>();
            _cache = cache;
        }


        /// <summary>
        /// The handler calls methods on the events which give the application control at certain points where processing is occurring. 
        /// If it is not provided a default instance is supplied which does nothing when the methods are called.
        /// </summary>
        protected new OAuth2IntrospectionEvents Events
        {
            get { return (OAuth2IntrospectionEvents)base.Events; }
            set { base.Events = value; }
        }

        /// <summary>
        /// Tries to authenticate a reference token on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = Options.TokenRetriever(Context.Request);

            if (token.IsMissing())
            {
                return ReportNonSuccessAndReturn(AuthenticateResult.NoResult());
            }

            if (token.Contains('.') && Options.SkipTokensWithDots)
            {
                _logger.LogTrace("Token contains a dot - skipped because SkipTokensWithDots is set.");
                return ReportNonSuccessAndReturn(AuthenticateResult.NoResult());
            }

            if (Options.EnableCaching)
            {
                var key = $"{Options.CacheKeyPrefix}{token}";
                var claims = await _cache.GetClaimsAsync(key).ConfigureAwait(false);
                if (claims != null)
                {
                    var ticket = await CreateTicket(claims);

                    _logger.LogTrace("Token found in cache.");

                    if (Options.SaveToken)
                    {
                        ticket.Properties.StoreTokens(new[]
                        {
                            new AuthenticationToken { Name = "access_token", Value = token }
                        });
                    }

                    return AuthenticateResult.Success(ticket);
                }

                _logger.LogTrace("Token is not cached.");
            }

            // Use a LazyAsync to ensure only one thread is requesting introspection for a token - the rest will wait for the result
            var lazyIntrospection = Options.LazyIntrospections.GetOrAdd(token, CreateLazyIntrospection);

            try
            {
                var response = await lazyIntrospection.Value.ConfigureAwait(false);

                if (response.IsError)
                {
                    _logger.LogError("Error returned from introspection endpoint: " + response.Error);
                    return ReportNonSuccessAndReturn(AuthenticateResult.Fail("Error returned from introspection endpoint: " + response.Error));
                }

                if (response.IsActive)
                {
                    var ticket = await CreateTicket(response.Claims);

                    if (Options.SaveToken)
                    {
                        ticket.Properties.StoreTokens(new[]
                        {
                            new AuthenticationToken {Name = "access_token", Value = token}
                        });
                    }

                    if (Options.EnableCaching)
                    {
                        var key = $"{Options.CacheKeyPrefix}{token}";
                        await _cache.SetClaimsAsync(key, response.Claims, Options.CacheDuration, _logger).ConfigureAwait(false);
                    }

                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    return ReportNonSuccessAndReturn(AuthenticateResult.Fail("Token is not active."));
                }
            }
            finally
            {
                // If caching is on and it succeeded, the claims are now in the cache.
                // If caching is off and it succeeded, the claims will be discarded.
                // Either way, we want to remove the temporary store of claims for this token because it is only intended for de-duping fetch requests
                Options.LazyIntrospections.TryRemove(token, out _);
            }
        }

        private AuthenticateResult ReportNonSuccessAndReturn(AuthenticateResult result)
        {
            Options.Events.OnAuthenticationFailed(result);
            return result;
        }

        private AsyncLazy<IntrospectionResponse> CreateLazyIntrospection(string token)
        {
            return new AsyncLazy<IntrospectionResponse>(() => LoadClaimsForToken(token));
        }

        private async Task<IntrospectionResponse> LoadClaimsForToken(string token)
        {
            var introspectionClient = await Options.IntrospectionClient.Value.ConfigureAwait(false);

            return await introspectionClient.SendAsync(new IntrospectionRequest
            {
                Token = token,
                TokenTypeHint = Options.TokenTypeHint,
                ClientId = Options.ClientId,
                ClientSecret = Options.ClientSecret
            }).ConfigureAwait(false);
        }

        private async Task<AuthenticationTicket> CreateTicket(IEnumerable<Claim> claims)
        {
            var authenticationType = Options.AuthenticationType ?? Scheme.Name;
            var id = new ClaimsIdentity(claims, authenticationType, Options.NameClaimType, Options.RoleClaimType);
            var principal = new ClaimsPrincipal(id);

            await Events.CreatingTicket(principal);

            return new AuthenticationTicket(principal, new AuthenticationProperties(), Scheme.Name);
        }
    }
}