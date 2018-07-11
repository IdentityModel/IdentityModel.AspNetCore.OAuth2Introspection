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
        /// Invoked after the provider successfully authenticates a user.
        /// </summary>
        /// <param name="principal">Contains claims set hydtrated from the introspection response <see cref="System.Security.Claims.ClaimsPrincipal"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task CreatingTicket(ClaimsPrincipal principal) => OnCreatingTicket(principal);
    }
}
