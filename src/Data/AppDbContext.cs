using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OrderApi.Models;

namespace OrderApi.Data;

public class AppDbContext : IdentityDbContext<AppUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<Order> Orders => Set<Order>();
}

public class Order
{
    public int Id { get; set; }
    public string OwnerId { get; set; } = "";     // FK to AppUser.Id — used by the ownership policy
    public decimal Total { get; set; }
    public string CardMasked { get; set; } = "";   // PAN never persisted unmasked
}
