using JWTpractice;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["JWT:Issuer"],
        ValidAudience = builder.Configuration["JWT:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthentication();
builder.Services.AddMvc();

// Add services to the container.
var app = builder.Build();

// Configure the HTTP request pipeline.

app.MapGet("/security/get", () => { return Results.Ok("Hello World"); }).RequireAuthorization();

app.MapPost("/security/login",
[AllowAnonymous] (User user) =>
{
    if(user.UserName == "example" && user.Password == "test")
    {
        //get issuer
        var issuer = app.Configuration["JWT:Issuer"];
        //get audience
        var audience = app.Configuration["JWT:Audience"];
        //get key
        var key = app.Configuration["JWT:Key"];
        //get token descriptor
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            //create new subject
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim("Id", Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                //claim email
                new Claim(JwtRegisteredClaimNames.Email, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            }),

            //expire in 5 minutes
            Expires = DateTime.UtcNow.AddMinutes(1),
            //issuer
            Issuer = issuer,
            //audience
            Audience = audience,
            //signing credentials
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha256Signature)
        };

        //token handler
        var tokenHandler = new JwtSecurityTokenHandler();
        //create token from descriptor
        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        var jwtToken = tokenHandler.WriteToken(token);
        var stringToken = tokenHandler.WriteToken(token);

        return Results.Ok(stringToken);
    }
    return Results.Unauthorized();
});

app.UseAuthentication();
app.UseAuthorization();
app.Run();

