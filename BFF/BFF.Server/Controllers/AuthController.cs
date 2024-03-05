﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace BFF.Server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        [Route("/Login")]
        public ActionResult Login(string returnUrl = "/")
        {
            return new ChallengeResult("OIDC", new AuthenticationProperties() { RedirectUri = returnUrl });
        }

        [Authorize]
        [Route("/Logout")]
        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            return new SignOutResult("OIDC", new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home")
            });
        }

        [Route("/User")]
        public ActionResult GetUser()
        {
            if (User.Identity.IsAuthenticated)
            {
                var claims = ((ClaimsIdentity)this.User.Identity).Claims.Select(c =>
                    new { type = c.Type, value = c.Value })
                    .ToArray();

                return Json(new { isAuthenticated = true, claims = claims });
            }

            return Json(new { isAuthenticated = false });
        }
    }
}
