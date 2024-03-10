using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization
{
    public class ScopeHandler : AuthorizationHandler<ScopeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var scope = "http://schemas.microsoft.com/identity/claims/scope";

            var success = context.User.Claims.Any(c => c.Type == scope &&  c.Value.Contains(requirement.Scope));

            if (success)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
