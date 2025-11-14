using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record RegisterRequest(
            [Required, EmailAddress] string Email,
            [Required, MinLength(4)] string Password);
}
