using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ResetPasswordRequest(
        [Required, EmailAddress] string Email,
        [Required] string Token,
        [Required] string NewPassword);
}
