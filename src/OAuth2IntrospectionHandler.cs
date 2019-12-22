// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using IdentityModel.AspNetCore.OAuth2Introspection.Infrastructure;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
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
        
        static readonly ConcurrentDictionary<string, Lazy<Task<AuthenticateResult>>> IntrospectionDictionary =
            new ConcurrentDictionary<string, Lazy<Task<AuthenticateResult>>>();

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

        /// <inheritdoc/>
        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new OAuth2IntrospectionEvents());

        /// <summary>
        /// Tries to authenticate a reference token on the current request
        /// </summary>
        /// <returns></returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string token = Options.TokenRetriever(Context.Request);

            // no token - nothing to do here
            if (token.IsMissing())
            {
                return AuthenticateResult.NoResult();
            }

            // if token contains a dot - it might be a JWT and we are skipping
            // this is configurable
            if (token.Contains('.') && Options.SkipTokensWithDots)
            {
                _logger.LogTrace("Token contains a dot - skipped because SkipTokensWithDots is set.");
                return AuthenticateResult.NoResult();
            }

            // if caching is enable - let's check if we have a cached introspection
            if (Options.EnableCaching)
            {
                var key = $"{Options.CacheKeyPrefix}{token}";
                var claims = await _cache.GetClaimsAsync(key).ConfigureAwait(false);
                if (claims != null)
                {
                    // find out if it is a cached inactive token
                    var isInActive = claims.FirstOrDefault(c => string.Equals(c.Type, "active", StringComparison.OrdinalIgnoreCase) && string.Equals(c.Value, "false", StringComparison.OrdinalIgnoreCase));
                    if (isInActive != null)
                    {
                        return await ReportNonSuccessAndReturn("Cached token is not active.");
                    }

                    return await CreateTicket(claims, token);
                }

                _logger.LogTrace("Token is not cached.");
            }
            
            // no cached result - let's make a network roundtrip to the introspection endpoint
            // this code block tries to make sure that we only do a single roundtrip, even when multiple requests
            // with the same token come in at the same time
            try
            {
                return await IntrospectionDictionary.GetOrAdd(token, _ =>
                {
                    return new Lazy<Task<AuthenticateResult>>(async () =>
                    {
                        var response = await LoadClaimsForToken(token);
                        
                        if (response.IsError)
                        {
                            _logger.LogError("Error returned from introspection endpoint: " + response.Error);
                            return await ReportNonSuccessAndReturn("Error returned from introspection endpoint: " + response.Error);
                        }
                
                        if (response.IsActive)
                        {
                            if (Options.EnableCaching)
                            {
                                var key = $"{Options.CacheKeyPrefix}{token}";
                                await _cache.SetClaimsAsync(key, response.Claims, Options.CacheDuration, _logger).ConfigureAwait(false);
                            }

                            return await CreateTicket(response.Claims, token);
                        }
                        else
                        {
                            if (Options.EnableCaching)
                            {
                                var key = $"{Options.CacheKeyPrefix}{token}";

                                // add an exp claim - otherwise caching will not work
                                var claimsWithExp = response.Claims.ToList();
                                claimsWithExp.Add(new Claim("exp",
                                    DateTimeOffset.UtcNow.Add(Options.CacheDuration).ToUnixTimeSeconds().ToString()));
                                await _cache.SetClaimsAsync(key, claimsWithExp, Options.CacheDuration, _logger)
                                    .ConfigureAwait(false);
                            }

                            return await ReportNonSuccessAndReturn("Token is not active.");
                        }
                    });
                }).Value;
            }
            finally
            {
                IntrospectionDictionary.TryRemove(token, out _);
            }
        }

        private async Task<AuthenticateResult> ReportNonSuccessAndReturn(string error)
        {
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Error = error
            };

            await Events.AuthenticationFailed(authenticationFailedContext);

            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            return AuthenticateResult.Fail(error);
        }

        private AsyncLazy<TokenIntrospectionResponse> CreateLazyIntrospection(string token)
        {
            return new AsyncLazy<TokenIntrospectionResponse>(() => LoadClaimsForToken(token));
        }

        private async Task<TokenIntrospectionResponse> LoadClaimsForToken(string token)
        {
            var introspectionClient = await Options.IntrospectionClient.Value.ConfigureAwait(false);
            return await introspectionClient.Introspect(token, Options.TokenTypeHint).ConfigureAwait(false);
        }

        private async Task<AuthenticateResult> CreateTicket(IEnumerable<Claim> claims, string token)
        {
            var authenticationType = Options.AuthenticationType ?? Scheme.Name;
            var id = new ClaimsIdentity(claims, authenticationType, Options.NameClaimType, Options.RoleClaimType);
            var principal = new ClaimsPrincipal(id);

            var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
            {
                Principal = principal,
                SecurityToken = token
            };

            await Events.TokenValidated(tokenValidatedContext);
            if (tokenValidatedContext.Result != null)
            {
                return tokenValidatedContext.Result;
            }

            if (Options.SaveToken)
            {
                tokenValidatedContext.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = "access_token", Value = token }
                });
            }

            tokenValidatedContext.Success();
            return tokenValidatedContext.Result;
        }
    }
}