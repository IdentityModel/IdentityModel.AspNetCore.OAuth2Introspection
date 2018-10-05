using Microsoft.AspNetCore.Authentication;
using System;
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
        /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
        /// </summary>
        public Func<ClaimsPrincipal, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Gets or sets the function that is invoked when authentication fails.
        /// </summary>
        public Func<AuthenticateResult, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked after the provider successfully authenticates a user.
        /// </summary>
        /// <param name="principal">Contains claims set hydtrated from the introspection response <see cref="System.Security.Claims.ClaimsPrincipal"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task CreatingTicket(ClaimsPrincipal principal) => OnCreatingTicket(principal);

        /// <summary>
        /// Invoked if and after authentication has failed.
        /// </summary>
        /// <param name="result">Contains the failed authentication result.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task AuthenticationFailed(AuthenticateResult result) => OnAuthenticationFailed(result);
    }
}
