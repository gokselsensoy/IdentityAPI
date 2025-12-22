using System.ComponentModel.DataAnnotations;

namespace IdentityApi.Models.RequestDTOs
{
    public record RequestEmailChangeRequest([Required, EmailAddress] string NewEmail);
}
