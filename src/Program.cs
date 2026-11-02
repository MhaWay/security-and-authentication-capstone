using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OrderApi.Data;
using OrderApi.Models;
using OrderApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Data protection: dedicated key ring persisted to a controlled path, application-scoped purpose.
builder.Services.AddDataProtection()
    .SetApplicationName("OrderApi")
    .PersistKeysToFileSystem(new DirectoryInfo(builder.Configuration["DataProtection:KeyPath"] ?? "keys"));

// Identity with hardened defaults (PBKDF2 hasher under the hood; no MD5/SHA1 anywhere).
builder.Services.AddIdentity<AppUser, IdentityRole>(o =>
{
    o.Password.RequiredLength = 10;
    o.Password.RequireUppercase = true;
    o.Password.RequireDigit = true;
    o.Lockout.MaxFailedAccessAttempts = 5;
    o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    o.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-+@";
}).AddEntityFrameworkStores<AppDbContext>();

// JWT signing key comes ONLY from the environment, never from appsettings (vuln #1 fixed).
var jwtKey = Environment.GetEnvironmentVariable("Jwt__Key")
    ?? throw new InvalidOperationException("Jwt__Key must be provided as an environment variable");
builder.Services.AddAuthentication().AddJwtBearer(o =>
{
    o.MapInboundClaims = false;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "orderapi",
        ValidateAudience = true,
        ValidAudience = "orderapi-clients",
        ValidateLifetime = true,
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtKey)),
        RequireSignedTokens = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("MustBeOwner", p => p.RequireAssertion(c =>
        c.User.FindFirst("sub")?.Value == c.User.FindFirst("order_owner")?.Value || c.IsInRole("Admin")))
    .AddPolicy("ManagerOnly", p => p.RequireRole("Manager", "Admin"));

// Fixed-window rate limiting: brute-force mitigation on login (vuln #5).
builder.Services.AddRateLimiter(o =>
{
    o.AddFixedWindowLimiter("login", l => { l.PermitLimit = 5; l.Window = TimeSpan.FromMinutes(1); });
    o.AddFixedWindowLimiter("api", l => { l.PermitLimit = 120; l.Window = TimeSpan.FromMinutes(1); });
});

builder.Services.AddControllers();
builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default")));
builder.Services.AddHttpsRedirection(o => o.HttpsPort = 5001);
builder.Services.AddHostedService<SessionCleanupService>();

var app = builder.Build();
app.UseExceptionHandler("/error");   // generic RFC 7807, never leak stack traces (vuln #7)
app.UseHsts();                       // HSTS (vuln #6)
app.UseHttpsRedirection();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
