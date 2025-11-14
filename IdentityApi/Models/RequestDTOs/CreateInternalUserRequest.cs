using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record CreateInternalUserRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(4)] string Password,
    [Required] string FullName,
    [Required] string Role);
}
