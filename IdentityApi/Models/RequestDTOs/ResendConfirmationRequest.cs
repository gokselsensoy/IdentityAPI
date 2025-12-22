using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record ResendConfirmationRequest([Required, EmailAddress] string Email);
}
