// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using IdentityModel.Client;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    public class OAuth2IntrospectionHandler : AuthenticationHandler<OAuth2IntrospectionOptions>
    {
        private readonly IDistributedCache _cache;
        private readonly AsyncLazy<IntrospectionClient> _client;
        private readonly ILogger<OAuth2IntrospectionHandler> _logger;
        private readonly ConcurrentDictionary<string, AsyncLazy<IntrospectionResponse>> _lazyTokenIntrospections = new ConcurrentDictionary<string, AsyncLazy<IntrospectionResponse>>();

        public OAuth2IntrospectionHandler(AsyncLazy<IntrospectionClient> client, ILoggerFactory loggerFactory, IDistributedCache cache)
        {
            _client = client;
            _logger = loggerFactory.CreateLogger<OAuth2IntrospectionHandler>();
            _cache = cache;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = Options.TokenRetriever(Context.Request);

            if (token.IsMissing())
            {
                return AuthenticateResult.Skip();
            }

            if (token.Contains('.') && Options.SkipTokensWithDots)
            {
                _logger.LogTrace("Token contains a dot - skipped because SkipTokensWithDots is set.");
                return AuthenticateResult.Skip();
            }

            if (Options.EnableCaching)
            {
                var claims = await _cache.GetClaimsAsync(token).ConfigureAwait(false);
                if (claims != null)
                {
                    _logger.LogTrace("Token found in cache.");
                    return AuthenticateResult.Success(CreateTicket(claims));
                }

                _logger.LogTrace("Token is not cached.");
            }
            
            // Use a LazyAsync to ensure only one thread is requesting introspection for a token - the rest will wait for the result
            var lazyIntrospection = _lazyTokenIntrospections.GetOrAdd(token, CreateLazyIntrospection);

            try
            {
                var response = await lazyIntrospection.Value.ConfigureAwait(false);

                if (response.IsError)
                {
                    _logger.LogError("Error returned from introspection endpoint: " + response.Error);
                    return AuthenticateResult.Fail("Error returned from introspection endpoint: " + response.Error);
                }

                if (response.IsActive)
                {
                    var ticket = CreateTicket(response.Claims);

                    if (Options.SaveToken)
                    {
                        ticket.Properties.StoreTokens(new[]
                        {
                            new AuthenticationToken {Name = "access_token", Value = token}
                        });
                    }

                    if (Options.EnableCaching)
                    {
                        await _cache.SetClaimsAsync(token, response.Claims, Options.CacheDuration, _logger).ConfigureAwait(false);
                    }

                    return AuthenticateResult.Success(ticket);
                }
                else
                {
                    return AuthenticateResult.Fail("Token is not active.");
                }
            }
            finally
            {
                // If caching is on and it succeeded, the claims are now in the cache.
                // If caching is off and it succeeded, the claims will be discarded.
                // Either way, we want to remove the temporary store of claims for this token because it is only intended for de-duping fetch requests
                AsyncLazy<IntrospectionResponse> removed;
                _lazyTokenIntrospections.TryRemove(token, out removed);
            }
        }

        private AsyncLazy<IntrospectionResponse> CreateLazyIntrospection(string token)
        {
            return new AsyncLazy<IntrospectionResponse>(() => LoadClaimsForToken(token));
        }

        private async Task<IntrospectionResponse> LoadClaimsForToken(string token)
        {
            var introspectionClient = await _client.Value.ConfigureAwait(false);

            return await introspectionClient.SendAsync(new IntrospectionRequest
            {
                Token = token,
                TokenTypeHint = OidcConstants.TokenTypes.AccessToken,
                ClientId = Options.ScopeName,
                ClientSecret = Options.ScopeSecret
            }).ConfigureAwait(false);
        }

        private AuthenticationTicket CreateTicket(IEnumerable<Claim> claims)
        {
            var id = new ClaimsIdentity(claims, Options.AuthenticationScheme, Options.NameClaimType, Options.RoleClaimType);
            var principal = new ClaimsPrincipal(id);

            return new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
        }
    }
}