using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

IConfiguration configuration = builder.Configuration;

builder.Services.Configure<KestrelServerOptions>(configuration.GetSection("Kestrel"));

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Events = new CookieAuthenticationEvents
        {
        // Following the validation of the authentication cookie, this event is triggered.
        // During this process, we check if the access token is nearing expiration.
        // If so, we utilize the refresh token to obtain a new access token and store both tokens.
        OnValidatePrincipal = async cookieCtx =>
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            string? expiresAt = cookieCtx.Properties.GetTokenValue("expires_at");
            if (expiresAt != null)
            {
                DateTimeOffset accessTokenExpiration = DateTimeOffset.Parse(expiresAt);
                    TimeSpan timeRemaining = accessTokenExpiration.Subtract(now);
                    int refreshThresholdMinutes = Convert.ToInt32(configuration["OIDC:RefreshThresholdMinutes"]);
                    TimeSpan refreshThreshold = TimeSpan.FromMinutes(refreshThresholdMinutes);

                    if (timeRemaining < refreshThreshold)
                    {
                        string? refreshToken = cookieCtx.Properties.GetTokenValue("refresh_token");
                        TokenResponse response = await new HttpClient().RequestRefreshTokenAsync(new RefreshTokenRequest
                        {
                            Address = configuration["OIDC:TokenUrl"],
                            ClientId = configuration["OIDC:ClientId"],
                            ClientSecret = configuration["OIDC:ClientSecret"],
                            RefreshToken = refreshToken
                        });

                        if (!response.IsError)
                        {
                            int expiresInSeconds = response.ExpiresIn;
                            DateTimeOffset updatedExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresInSeconds);
                            cookieCtx.Properties.UpdateTokenValue("expires_at", updatedExpiresAt.ToString());
                            cookieCtx.Properties.UpdateTokenValue("access_token", response.AccessToken);
                            cookieCtx.Properties.UpdateTokenValue("refresh_token", response.RefreshToken);

                            // Inform the cookie middleware to regenerate the cookie as it has been modified.
                            cookieCtx.ShouldRenew = true;
                        }
                    }
                }
            }
        };
    })
    .AddOpenIdConnect("OIDC", options => ConfigureOpenIdConnect(options, configuration));

builder.Services.AddHttpClient();

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddHsts(options =>
{
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.MapFallbackToFile("index.html");

app.Run();

static void ConfigureOpenIdConnect(OpenIdConnectOptions options, IConfiguration configuration)
{
    // Set the authority to your OIDC domain
    options.Authority = configuration["OIDC:Domain"];
    options.MetadataAddress = configuration["OIDC:MetadataAddress"];

    // Configure the OIDC Client ID and Client Secret
    options.ClientId = configuration["OIDC:ClientId"];
    options.ClientSecret = configuration["OIDC:ClientSecret"];

    // Set response type to code
    options.ResponseType = OpenIdConnectResponseType.Code;

    options.ResponseMode = OpenIdConnectResponseMode.FormPost;

    // Configure the scope
    options.Scope.Clear();
    options.Scope.Add("email");
    options.Scope.Add("profile");
    options.Scope.Add("openid");

    options.CallbackPath = new PathString("/callback");

    // Configure the Claims Issuer to be OIDC
    options.ClaimsIssuer = "OIDC";

    options.SaveTokens = true;

    options.Events = new OpenIdConnectEvents
    {
        // handle the logout redirection
        OnRedirectToIdentityProviderForSignOut = (context) =>
        {
            var logoutUri = configuration["OIDC:LogoutUri"];

            var postLogoutUri = context.Properties.RedirectUri;
            if (!string.IsNullOrEmpty(postLogoutUri))
            {
                if (postLogoutUri.StartsWith("/"))
                {
                    // transform to absolute
                    var request = context.Request;
                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                }
                logoutUri += $"?redirect_uri={Uri.EscapeDataString(postLogoutUri)}";
            }
            context.Response.Redirect(logoutUri);
            context.HandleResponse();

            return Task.CompletedTask;
        },
        OnRedirectToIdentityProvider = context =>
        {
            // Set Audience
            context.ProtocolMessage.SetParameter("audience", configuration["OIDC:ApiAudience"]);
            return Task.CompletedTask;
        }
    };
}