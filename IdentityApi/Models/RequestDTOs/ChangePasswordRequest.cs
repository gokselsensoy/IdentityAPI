using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ChangePasswordRequest(
        [Required] string CurrentPassword,
        [Required] string NewPassword);
}
