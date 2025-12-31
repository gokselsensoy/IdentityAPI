using IdentityApi.Domain;
using IdentityApi.Infrastructure;
using IdentityApi.Services.Abstracts;
using IdentityApi.Services.Concrete;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;
using Serilog;
using System.Reflection;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("C:/Logs/IdentityApi/startup-log-.txt", rollingInterval: RollingInterval.Day) // Sunucu debug için
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // 2. Serilog Host Entegrasyonu
    builder.Host.UseSerilog((context, services, configuration) => configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .WriteTo.Console());

    // 3. CORS Ayarları (Frontend'in Identity'e erişebilmesi için şart)
    var corsSettings = builder.Configuration.GetSection("CorsSettings");
    var allowedOrigins = corsSettings.GetSection("AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();

    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowSpecificOrigins", policyBuilder =>
        {
            if (allowedOrigins.Any())
            {
                policyBuilder.WithOrigins(allowedOrigins)
                             .AllowAnyHeader()
                             .AllowAnyMethod()
                             .AllowCredentials();
            }
            else
            {
                policyBuilder.AllowAnyOrigin()
                             .AllowAnyHeader()
                             .AllowAnyMethod()
                             .AllowCredentials();
            }
        });
    });

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

    builder.Services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(2));
    builder.Services.Configure<DataProtectionTokenProviderOptions>("EmailConfirmation", options => options.TokenLifespan = TimeSpan.FromMinutes(15));
    builder.Services.Configure<DataProtectionTokenProviderOptions>("PasswordReset", options => options.TokenLifespan = TimeSpan.FromMinutes(30));

    // --- Dynamic Issuer URL ---
    var issuerUrl = builder.Configuration["GeneralSettings:IssuerUrl"];
    if (string.IsNullOrEmpty(issuerUrl)) throw new Exception("GeneralSettings:IssuerUrl appsettings dosyasında bulunamadı!");

    // 4. OpenIddict Konfigürasyonu
    builder.Services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore().UseDbContext<IdentityDbContext>();
        })
        .AddServer(options =>
        {
            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token", "/api/token/generate-for-profile")
                   .SetRevocationEndpointUris("/connect/revoke")
                   .SetUserInfoEndpointUris("/connect/userinfo");

            // Config'den gelen URL'i kullan
            options.SetIssuer(new Uri(issuerUrl));

            options.AllowPasswordFlow();
            options.AllowRefreshTokenFlow();
            options.AllowClientCredentialsFlow();
            options.AllowCustomFlow("profile_exchange");

            // --- SERTİFİKA AYARI (ÖNEMLİ) ---
            if (builder.Environment.IsDevelopment())
            {
                // Development ortamında standart dev sertifikaları
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                options.DisableAccessTokenEncryption();
            }
            else
            {
                // Production/Test ortamında "Ephemeral" (Geçici) anahtarlar
                // Not: Sunucu yeniden başlatılırsa login olanların token'ı geçersiz kalır.
                // Gerçek Prod için .pfx dosyası yüklenmelidir (AddEncryptionCertificate).
                options.AddEphemeralEncryptionKey()
                       .AddEphemeralSigningKey();

                options.DisableAccessTokenEncryption(); // Test kolaylığı için şifrelemeyi kapattım, prod için açılabilir.
            }

            options.UseAspNetCore()
                   .EnableTokenEndpointPassthrough()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableUserInfoEndpointPassthrough();
        })
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();
        });

    builder.Services.AddDbContext<IdentityDbContext>(options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString("IdentityConnection"));
        options.UseOpenIddict();
    });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy("InternalApiAccess", policy =>
        {
            policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
            policy.RequireClaim("client_id", "logistics_api_service");
        });
    });

    builder.Services.AddHostedService<MigrationService>();
    builder.Services.AddHostedService<RoleSeedingService>();
    builder.Services.AddHostedService<ClientRegistrationWorker>();
    builder.Services.AddHostedService<ScopeRegistrationWorker>();

    builder.Services.AddSingleton<IEmailService, LogToConsoleEmailService>();

    builder.Services.AddHttpClient<IIntegrationService, HttpWebhookIntegrationService>(client =>
    {
        client.BaseAddress = new Uri(builder.Configuration["IntegrationSettings:LogisticsApiBaseUrl"]);
    });

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();

    // --- Swagger ---
    builder.Services.AddSwaggerGen(options =>
    {
        options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = Microsoft.OpenApi.Models.ParameterLocation.Header,
            Description = "JWT Authorization header using the Bearer scheme."
        });

        options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
        {
            {
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Reference = new Microsoft.OpenApi.Models.OpenApiReference { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" }
                },
                new string[] {}
            }
        });
    });

    var app = builder.Build();

    // Swagger her ortamda açık
    app.UseSwagger();
    app.UseSwaggerUI();

    app.UseHttpsRedirection();

    // Serilog Request Logging (UseRouting'den önce olsa iyi olur ama şart değil)
    app.UseSerilogRequestLogging();

    app.UseRouting();

    // CORS Middleware Eklendi
    app.UseCors("AllowSpecificOrigins");

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "IdentityApi Host terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}