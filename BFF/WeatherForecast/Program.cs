using Api.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

IConfiguration configuration = builder.Configuration;

// Add services to the container.

var authentication = builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                   .AddJwtBearer("Bearer", c =>
                   {
                       c.Authority = configuration["OAuth2:Domain"];
                       c.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                       {
                           ValidateAudience = true,
                           ValidAudiences = configuration["OAuth2:Audience"].Split(";"),
                           ValidateIssuer = true,
                           ValidIssuer = configuration["OAuth2:Domain"]
                       };
                   });


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IAuthorizationHandler, ScopeHandler>();

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

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
