using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using OrderApi.Models;

namespace OrderApi.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<AppUser> _users;
    private readonly SymmetricSecurityKey _key;

    public AuthController(UserManager<AppUser> users)
    {
        _users = users;
        _key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("Jwt__Key")!));
    }

    // 5 requests/min per IP — brute-force mitigation (vuln #5 fixed here)
    [EnableRateLimiting("login")]
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(new ProblemDetails { Title = "Invalid payload" });
        var user = await _users.FindByNameAsync(dto.Username);
        if (user is null || !await _users.CheckPasswordAsync(user, dto.Password))
            return Unauthorized(new ProblemDetails { Title = "Invalid credentials" }); // no user enumeration

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        foreach (var role in await _users.GetRolesAsync(user))
            claims.Add(new Claim(ClaimTypes.Role, role));

        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);
        var jwt = new JwtSecurityToken(
            issuer: "orderapi", audience: "orderapi-clients", claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(15),   // short-lived access token (vuln #3)
            signingCredentials: creds);
        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(jwt), expiresIn = 900 });
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var user = new AppUser
        {
            UserName = dto.Username,
            Email = dto.Email,
            CustomerCardMasked = Mask.MaskPan(dto.CardNumber)
        };
        var result = await _users.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(new ProblemDetails { Title = "Registration failed" });
        await _users.AddToRoleAsync(user, "User");
        return Ok();
    }
}
