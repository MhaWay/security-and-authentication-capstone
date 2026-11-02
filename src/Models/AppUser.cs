using Microsoft.AspNetCore.Identity;

namespace OrderApi.Models;

public class AppUser : IdentityUser
{
    // Stored masked (static masking) — raw card number never persists (vuln #8)
    public string? CustomerCardMasked { get; set; }
}
