using System.ComponentModel.DataAnnotations;

namespace OrderApi.Models;

public record LoginDto(
    [Required][RegularExpression("^[a-zA-Z0-9._+@-]{1,64}$", ErrorMessage = "Invalid characters in username")]
    string Username,
    [Required][MinLength(10)] string Password);

public record RegisterDto(
    [Required] string Username,
    [EmailAddress][Required] string Email,
    [Required][MinLength(10)] string Password,
    string? CardNumber);
