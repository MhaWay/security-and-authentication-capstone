using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using OrderApi.Data;

namespace OrderApi.Controllers;

[ApiController]
[Route("orders")]
[Authorize]
public class OrdersController : ControllerBase
{
    private readonly AppDbContext _db;
    public OrdersController(AppDbContext db) => _db = db;

    [HttpGet]
    [Authorize(Roles = "Manager,Admin")]
    public async Task<IActionResult> List() =>
        Ok(await _db.Orders.AsNoTracking().ToListAsync());

    // Policy-based: ownership OR admin — kills the IDOR (vuln #4).
    // EF generates parameterized SQL — no string concatenation, no SQL injection.
    [HttpGet("{id:int}")]
    [Authorize(Policy = "MustBeOwner")]
    public async Task<IActionResult> Get(int id)
    {
        var order = await _db.Orders.FindAsync(id);
        return order is null ? NotFound() : Ok(order);
    }
}
