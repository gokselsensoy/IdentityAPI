using IdentityApi.Domain;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityApi.Controllers
{
    [Route("api/token")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public TokenController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost("generate-for-profile")]
        // [FromBody] Kaldırıldı! Parametre almana gerek yok, Request'ten okuyacağız.
        public async Task<IActionResult> GenerateForProfile()
        {
            // 1. OpenIddict'in parse ettiği isteği al
            var request = HttpContext.GetOpenIddictServerRequest();

            // Eğer istek null ise (Parse edilemediyse)
            if (request == null)
            {
                return BadRequest("İstek formatı geçersiz. (x-www-form-urlencoded olmalı)");
            }

            // 2. Parametreleri Oku (request["key"] şeklinde)
            // Client tarafında gönderdiğimiz key isimleriyle aynı olmalı.
            var userIdStr = (string?)request["user_id"];
            var companyIdStr = (string?)request["company_id"];
            var profileType = (string?)request["profile_type"];

            // Roller liste olarak gelebilir (GetParameter parametre adıdır)
            var rolesParam = request.GetParameter("roles");
            var roles = new List<string>();

            // 2. Parametre dolu mu kontrol et
            if (rolesParam.HasValue)
            {
                // 3. Nullable wrapper'dan kurtulup gerçek veriye (.Value) ulaş
                // Ve bunu JsonElement'e cast et (OpenIddict veriyi böyle tutar)
                var element = (System.Text.Json.JsonElement)rolesParam.Value;

                // 4. Veri Tipi Kontrolü (Dizi mi, Tekil mi?)
                if (element.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    // Eğer ["Admin", "User"] gibi dizi geldiyse
                    foreach (var item in element.EnumerateArray())
                    {
                        var r = item.GetString();
                        if (!string.IsNullOrEmpty(r)) roles.Add(r);
                    }
                }
                else
                {
                    // Eğer "Admin" gibi tekil geldiyse
                    var r = element.GetString();
                    if (!string.IsNullOrEmpty(r)) roles.Add(r);
                }
            }

            if (string.IsNullOrEmpty(userIdStr)) return BadRequest("User ID zorunludur.");

            // 3. Kullanıcıyı Bul
            var user = await _userManager.FindByIdAsync(userIdStr);
            if (user == null) return NotFound("Kullanıcı bulunamadı.");

            // 4. Principal Oluştur (Manuel DTO yerine buradaki değişkenleri kullanıyoruz)
            var principal = await CreatePrincipalAsync(user, companyIdStr, profileType, roles);

            // 5. Token Bas
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // CreatePrincipalAsync Metodunu da yeni parametrelere göre güncelle:
        private async Task<ClaimsPrincipal> CreatePrincipalAsync(ApplicationUser user, string? companyId, string? profileType, List<string?> roles)
        {
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var identity = (ClaimsIdentity)principal.Identity!;

            var subjectClaim = identity.FindFirst(Claims.Subject);
            if (subjectClaim == null)
            {
                // Eğer Identity NameIdentifier varsa onu al, yoksa user.Id kullan
                var userId = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? user.Id.ToString();

                // "sub" claim'ini ekle
                identity.AddClaim(new Claim(Claims.Subject, userId));
            }

            var scopes = new HashSet<string>
            {
                Scopes.OpenId,
                Scopes.Email,
                Scopes.Profile,
                Scopes.OfflineAccess,
                "logistics_api",
                Scopes.Roles
            };
            principal.SetScopes(scopes);

            // Parametreleri Claim'e dönüştür
            if (!string.IsNullOrEmpty(companyId))
            {
                identity.AddClaim(new Claim("company_id", companyId));
            }

            if (!string.IsNullOrEmpty(profileType))
            {
                identity.AddClaim(new Claim("profile_type", profileType));
            }

            if (roles != null && roles.Any())
            {
                foreach (var role in roles)
                {
                    if (!string.IsNullOrEmpty(role))
                        identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
            }

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return principal;
        }

        // Hangi claim nereye gidecek?
        private IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
        {
            // 1. Access Token'a her zaman gitmeli
            yield return Destinations.AccessToken;

            // 2. Eğer "openid" scope'u varsa ve claim hassas değilse ID Token'a da gitsin
            if (principal.HasScope(Scopes.OpenId))
            {
                switch (claim.Type)
                {
                    case Claims.Name:
                    case Claims.Email:
                    case "company_id":   // Bizim özel claim
                    case "profile_type": // Bizim özel claim
                        yield return Destinations.IdentityToken;
                        yield break;
                }
            }
        }
    }

    // DTO
    public class GenerateTokenRequest
    {
        public Guid UserId { get; set; }
        public Guid? CompanyId { get; set; }
        public string ProfileType { get; set; } // "Worker", "Freelancer"
        public List<string> Roles { get; set; }
    }
}
