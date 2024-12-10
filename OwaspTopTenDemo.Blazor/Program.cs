using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OwaspTopTenDemo.Blazor.Services;
using System.Net.Http;
using System.Net.Http.Headers;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

// Register HttpClient
var baseAddress = builder.Configuration.GetValue<string>("BaseAddress");
builder.Services.AddScoped(sp => new HttpClient(new AuthenticatedHttpClientHandler(sp.GetRequiredService<TokenService>()))
{
    BaseAddress = new Uri(baseAddress)
});

// Register authentication services
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<ProtectedLocalStorage>();
builder.Services.AddAuthorizationCore();

// Add logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.All; // Log all fields
    logging.RequestHeaders.Add("User-Agent"); // Log specific request headers
    logging.ResponseHeaders.Add("Content-Type"); // Log specific response headers
    logging.MediaTypeOptions.AddText("application/json"); // Log specific media types
    logging.RequestBodyLogLimit = 4096; // Set request body log limit
    logging.ResponseBodyLogLimit = 4096; // Set response body log limit
});

var app = builder.Build();
app.UseHttpLogging();
// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();