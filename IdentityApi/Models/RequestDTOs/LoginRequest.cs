using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record LoginRequest(
        [Required, EmailAddress] string Email,
        [Required] string Password,
        string? DeviceId = null);
}
