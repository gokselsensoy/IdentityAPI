using IdentityApi.Domain;
using IdentityApi.Infrastructure;
using IdentityApi.Services.Abstracts;
using IdentityApi.Services.Concrete;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// 1. EF Core ve Identity için DbContext'i ekle
builder.Services.AddDbContext<IdentityDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("IdentityConnection"));
    // OpenIddict'in EF Core entegrasyonunu etkinleştir
    options.UseOpenIddict();
});

// 2. ASP.NET Core Identity'yi ekle
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;

    options.Password.RequireDigit = false;
    options.Password.RequiredLength = 4;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.User.RequireUniqueEmail = true;

    options.Tokens.EmailConfirmationTokenProvider = "EmailConfirmation";
    options.Tokens.PasswordResetTokenProvider = "PasswordReset";
})
    .AddEntityFrameworkStores<IdentityDbContext>()
    .AddDefaultTokenProviders()
    .AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>("EmailConfirmation")
    .AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>("PasswordReset");

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    // Tüm token'lar için varsayılan süre
    options.TokenLifespan = TimeSpan.FromHours(2);
});

builder.Services.Configure<DataProtectionTokenProviderOptions>("EmailConfirmation", options =>
{
    // Email onay token'ı için özel süre (örn: 15 dakika)
    options.TokenLifespan = TimeSpan.FromMinutes(15);
});

builder.Services.Configure<DataProtectionTokenProviderOptions>("PasswordReset", options =>
{
    // Şifre sıfırlama token'ı için özel süre (örn: 30 dakika)
    options.TokenLifespan = TimeSpan.FromMinutes(30);
});

// 3. OpenIddict'i yapılandır
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<IdentityDbContext>()
               .ReplaceDefaultEntities<Guid>();
    })
    .AddServer(options =>
    {
        // Token, Authorize, UserInfo gibi endpoint'leri aktif et
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetRevocationEndpointUris("/connect/revoke")
               .SetUserInfoEndpointUris("/connect/userinfo");

        // OAuth 2.0 Akışları:
        // Mobil/Web "password" akışına izin ver (Kullanıcı Adı/Şifre)
        options.AllowPasswordFlow();
        // İleride tarayıcı tabanlı (PKCE) için:
        // options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        // Token yenileme
        options.AllowRefreshTokenFlow();
        options.AllowClientCredentialsFlow(); // 1. Client Credentials akışına izin ver

        // Geliştirme ortamı için geçici imzalama ve şifreleme sertifikaları
        // Production'da X.509 sertifikası kullanmalıyız.
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // ASP.NET Core (Authentication, Cookies) ile entegre et
        options.UseAspNetCore()
               .EnableTokenEndpointPassthrough()
               .EnableAuthorizationEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough();
    })
    .AddValidation(options => // Sunucunun kendi token'larını da doğrulayabilmesi için
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("InternalApiAccess", policy =>
    {
        // Token'ın "client_id" claim'ini kontrol et
        policy.RequireClaim("client_id", "logistics_api_service");
        // policy.RequireScope("internal_api"); 
    });
});

builder.Services.AddHostedService<ClientRegistration>();

// === Email Servisi ===
// IEmailService ve somut bir implementasyon eklemeliyiz
// Şimdilik test için konsola yazan bir servis ekleyelim
builder.Services.AddSingleton<IEmailService, LogToConsoleEmailService>();

// === Webhook Servisi ===
// IdentityAPI'nin LogisticsAPI'ye haber vermesi için bir servis
builder.Services.AddHttpClient<IIntegrationService, HttpWebhookIntegrationService>(client =>
{
    // LogisticsAPI'nin adresini appsettings'den okuyacağız
    client.BaseAddress = new Uri(builder.Configuration["IntegrationSettings:LogisticsApiBaseUrl"]);
    // TODO: Buraya bir API Key veya client credentials ile güvenlik eklenmeli
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Veritabanını oluştur/güncelle (Demo için)
// Production'da `dotnet ef database update` kullanılmalı
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    context.Database.Migrate();
}

app.Run();
