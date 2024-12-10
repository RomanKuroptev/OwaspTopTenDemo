using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using OwaspTopTenDemo.Api;
using OwaspTopTenDemo.Api.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

// Existing service registrations
builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});
builder.Services.AddSingleton<HtmlEncoder>(HtmlEncoder.Default);
builder.Services.AddScoped<UserService>();
builder.Services.AddScoped<HtmlEncodingService>();
builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = Microsoft.AspNetCore.HttpLogging.HttpLoggingFields.All; // Log all fields
    logging.RequestHeaders.Add("User-Agent"); // Log specific request headers
    logging.ResponseHeaders.Add("Content-Type"); // Log specific response headers
    logging.MediaTypeOptions.AddText("application/json"); // Log specific media types
    logging.RequestBodyLogLimit = 4096; // Set request body log limit
    logging.ResponseBodyLogLimit = 4096; // Set response body log limit
});

// Add memory cache service
builder.Services.AddMemoryCache();

// Add authentication services
var key = Encoding.ASCII.GetBytes("s1JRUTrWQpVdljwcEn8OJU3PvwKsc6WY"); // Replace with your secret key
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateLifetime = true,
        LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
        {
            var jwtToken = securityToken as JwtSecurityToken;
            if (jwtToken == null)
            {
                var jsonWebToken = securityToken as Microsoft.IdentityModel.JsonWebTokens.JsonWebToken;
                if (jsonWebToken != null)
                {
                    var token = jsonWebToken.EncodedToken;
                    return !TokenBlacklist.Contains(token) && expires > DateTime.UtcNow;
                }
                return false;
            }
            var tokenString = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            return !TokenBlacklist.Contains(tokenString) && expires > DateTime.UtcNow;
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

// Existing middleware
app.UseCors();

// Add authentication middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.UseHttpLogging();
app.UseDeveloperExceptionPage();

// Set up SQLite database
var connectionString = "Data Source=demo.db";
using (var connection = new SqliteConnection(connectionString))
{
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = @"
        DROP TABLE IF EXISTS Users;
        CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Password TEXT,
            PasswordHash TEXT,
            Role TEXT NOT NULL
        );
    ";
    command.ExecuteNonQuery();

    // Insert initial users
    command.CommandText = @"
        INSERT INTO Users (Username, PasswordHash, Role) VALUES 
        ('admin', @adminPasswordHash, 'Admin'),
        ('user', @userPasswordHash, 'User');
    ";
    command.Parameters.AddWithValue("@adminPasswordHash", BCrypt.Net.BCrypt.HashPassword("adminpassword"));
    command.Parameters.AddWithValue("@userPasswordHash", BCrypt.Net.BCrypt.HashPassword("password"));
    command.ExecuteNonQuery();
}

app.Run();
