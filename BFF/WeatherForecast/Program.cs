using Api.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using WeatherForecast.Middleware;

var builder = WebApplication.CreateBuilder(args);

IConfiguration configuration = builder.Configuration;

// Add services to the container.
builder.Services
                    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer("Bearer", c =>
                    {
                        c.Authority = builder.Configuration.GetSection("OAuth2:AuthorizeUrl").Get<string>();
                        c.MetadataAddress = builder.Configuration.GetSection("OAuth2:MetadataAddress").Get<string>();

                        c.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                        {
                            ValidateAudience = true,
                            ValidAudiences = builder.Configuration.GetSection("OAuth2:Audience").Get<string>().Split(";"),
                            ValidateIssuer = true,
                            ValidIssuer = builder.Configuration.GetSection("OAuth2:AuthorizeUrl").Get<string>()
                        };
                    });

builder.Services.AddControllers();
builder.Services.AddScoped<RequiresServiceContextFilter>();
builder.Services.AddMvc(options => options.Filters.Add<RequiresServiceContextFilter>());

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSwaggerGen();
//ilder.Services.Configure<KestrelServerOptions>(builder.Configuration.GetSection("Kestrel"));
builder.Services.AddSingleton<IAuthorizationHandler, ScopeHandler>();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();


builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("read:weather", p => p.RequireAuthenticatedUser().RequireScope("read:weather"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();

app.UseHttpsRedirection();

app.UseRouting();
app.UseAuthorization();

app.MapControllers();

app.Run();