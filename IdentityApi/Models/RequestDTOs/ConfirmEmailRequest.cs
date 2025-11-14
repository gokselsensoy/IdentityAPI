using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ConfirmEmailRequest([Required] Guid UserId, [Required] string Token);
}
