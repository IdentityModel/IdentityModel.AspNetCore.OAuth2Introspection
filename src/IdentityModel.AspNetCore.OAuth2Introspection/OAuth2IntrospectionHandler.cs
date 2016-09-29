// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
        private readonly LazyAsync<IntrospectionClient> _client;
        private readonly ILogger<OAuth2IntrospectionHandler> _logger;
        private static readonly KeyedSemaphore _keyedSemaphore = new KeyedSemaphore();

        public OAuth2IntrospectionHandler(LazyAsync<IntrospectionClient> client, ILoggerFactory loggerFactory, IDistributedCache cache)
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

                // We actually need to go and fetch the claims from the server because we don't have them cached.
                // It would be wasteful if we sent a request and another thread is already doing it.
                // If that's the case we'll wait here.
                var release = await _keyedSemaphore.WaitForKey(token).ConfigureAwait(false);

                try
                {
                    // Let's check the cache again in case the last thread populated it
                    claims = await _cache.GetClaimsAsync(token).ConfigureAwait(false);
                    if (claims != null)
                    {
                        return AuthenticateResult.Success(CreateTicket(claims));
                    }

                    var response = await GetClaims(token).ConfigureAwait(false);
                    if (response.AuthenticateResult.Succeeded)
                    {
                        await _cache.SetClaimsAsync(token, response.Claims, Options.CacheDuration, _logger).ConfigureAwait(false);
                    }
                    return response.AuthenticateResult;
                }
                finally
                {
                    release.Release();
                }
            }

            // Caching is turned off, lets fetch the claims fresh every time
            var claimsResponse = await GetClaims(token).ConfigureAwait(false);
            return claimsResponse.AuthenticateResult;
        }

        private async Task<ClaimsResponse> GetClaims(string token)
        {
            var introspectionClient = await _client.GetValueAsync().ConfigureAwait(false);

            var response = await introspectionClient.SendAsync(new IntrospectionRequest
            {
                Token = token,
                ClientId = Options.ScopeName,
                ClientSecret = Options.ScopeSecret
            }).ConfigureAwait(false);

            if (response.IsError)
            {
                return new ClaimsResponse { AuthenticateResult = AuthenticateResult.Fail("Error returned from introspection endpoint: " + response.Error) };
            }

            if (response.IsActive)
            {
                var ticket = CreateTicket(response.Claims);

                if (Options.SaveToken)
                {
                    ticket.Properties.StoreTokens(new[]
                    {
                        new AuthenticationToken { Name = "access_token", Value = token }
                    });
                }

                return new ClaimsResponse { AuthenticateResult = AuthenticateResult.Success(ticket), Claims = response.Claims };
            }
            else
            {
                return new ClaimsResponse { AuthenticateResult = AuthenticateResult.Fail("Token is not active.") };
            }
        }

        private AuthenticationTicket CreateTicket(IEnumerable<Claim> claims)
        {
            var id = new ClaimsIdentity(claims, Options.AuthenticationScheme, Options.NameClaimType, Options.RoleClaimType);
            var principal = new ClaimsPrincipal(id);

            return new AuthenticationTicket(principal, new AuthenticationProperties(), Options.AuthenticationScheme);
        }
        private class ClaimsResponse
        {
            public AuthenticateResult AuthenticateResult;
            public IEnumerable<Claim> Claims;
        }
    }
}