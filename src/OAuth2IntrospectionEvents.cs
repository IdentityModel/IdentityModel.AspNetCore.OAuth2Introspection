// Copyright (c) Dominick Baier & Brock Allen. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.OAuth2Introspection
{
    /// <summary>
    /// Default implementation.
    /// </summary>
    public class OAuth2IntrospectionEvents
    {
        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when client assertion need to be updated.
        /// </summary>
        public Func<UpdateClientAssertionContext, Task> OnUpdateClientAssertion { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when sending token introspection request.
        /// </summary>
        public Func<SendingRequestContext, Task> OnSendingRequest { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked before the ClaimsIdentity has been generated to allow extra claims to be extracted from the introspection response.
        /// </summary>
        public Func<ParseExtraClaimsContext, Task<IEnumerable<Claim>>> OnParseExtraClaims { get; set; } = context => Task.FromResult(Enumerable.Empty<Claim>());

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked after the security token has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public virtual Task TokenValidated(TokenValidatedContext context) => OnTokenValidated(context);

        /// <summary>
        /// Invoked when client assertion need to be updated.
        /// </summary>
        public virtual Task UpdateClientAssertion(UpdateClientAssertionContext context) => OnUpdateClientAssertion(context);

        /// <summary>
        /// Invoked when sending token introspection request.
        /// </summary>
        public virtual Task SendingRequest(SendingRequestContext context) => OnSendingRequest(context);

        /// <summary>
        /// Invoked before the ClaimsIdentity has been generated to allow extra claims to be extracted from the introspection response.
        /// </summary>
        public virtual Task<IEnumerable<Claim>> ParseExtraClaims(ParseExtraClaimsContext context) => OnParseExtraClaims(context);
    }
}
