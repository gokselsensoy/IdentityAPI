using IdentityApi.Domain;
using IdentityApi.Models.RequestDTOs;
using IdentityApi.Models.ResponseDTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    // Bu endpointleri sadece yetkili servisler (LogisticsAPI gibi) çağırmalı.
    // OpenIddict Validation ile korunabilir veya Client Credentials Flow ile korunabilir.
    // Şimdilik geliştirme aşamasında [AllowAnonymous] veya [Authorize] durumunu kendine göre ayarla.
    // [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)] 
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpGet("by-email")]
        public async Task<ActionResult<UserDto>> GetByEmail([FromQuery] string email)
        {
            if (string.IsNullOrEmpty(email)) return BadRequest("Email boş olamaz.");

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return NotFound();
            }

            return Ok(new UserDto
            {
                // DEĞİŞİKLİK: IdentityUser Id string tutar, DTO Guid istiyorsa çevirmelisin.
                Id = user.Id,
                Email = user.Email,
                UserName = user.UserName
            });
        }

        [HttpPost("{id}/roles")]
        public async Task<IActionResult> AddToRole(Guid id, [FromBody] AddRoleRequest request)
        {
            var user = await _userManager.FindByIdAsync(id.ToString());
            if (user == null)
            {
                return NotFound("Kullanıcı bulunamadı.");
            }

            if (!await _roleManager.RoleExistsAsync(request.Role))
            {
                return BadRequest($"'{request.Role}' isimli rol sistemde bulunamadı. Lütfen geçerli bir rol giriniz.");
            }

            // Kullanıcı zaten bu rolde mi?
            if (await _userManager.IsInRoleAsync(user, request.Role))
            {
                return Ok(new { Message = "Kullanıcı zaten bu role sahip." });
            }

            // Rolü ekle
            var result = await _userManager.AddToRoleAsync(user, request.Role);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new { Message = "Rol başarıyla eklendi." });
        }
    }
}
