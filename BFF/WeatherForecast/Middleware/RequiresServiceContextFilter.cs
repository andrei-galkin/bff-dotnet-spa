using Microsoft.AspNetCore.Mvc.Filters;

namespace WeatherForecast.Middleware
{
    public class RequiresServiceContextFilter : IActionFilter
    {
        public void OnActionExecuting(ActionExecutingContext context) { }

        public void OnActionExecuted(ActionExecutedContext context) { }
    }
}
