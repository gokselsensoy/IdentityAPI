using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ConfirmEmailChangeRequest([Required] string Token);
}
