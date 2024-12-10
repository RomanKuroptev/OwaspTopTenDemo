using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using OwaspTopTenDemo.Api.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OwaspTopTenDemo.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly string _secretKey = "s1JRUTrWQpVdljwcEn8OJU3PvwKsc6WY"; // Ensure this key matches the one in Program.cs
        private readonly UserService _userService;
        private readonly IMemoryCache _cache;

        public AuthController(UserService userService, IMemoryCache cache)
        {
            _userService = userService;
            _cache = cache;
        }

        [HttpPost("insecure-login")]
        public async Task<IActionResult> InsecureLogin([FromBody] LoginModel login)
        {
            var (isValid, role) = await _userService.ValidateUserAsync(login.Username, login.Password);
            if (isValid)
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_secretKey);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, login.Username),
                        new Claim(ClaimTypes.Role, role)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                return Ok(new { Token = tokenString });
            }

            return Unauthorized();
        }

        [HttpPost("secure-login")]
        public async Task<IActionResult> SecureLogin([FromBody] LoginModel login)
        {
            var cacheKey = $"LoginAttempts_{login.Username}";
            if (_cache.TryGetValue(cacheKey, out int attempts) && attempts >= 5)
            {
                return StatusCode(429, "Too many login attempts. Please try again later.");
            }

            var (isValid, role) = await _userService.ValidateUserAsync(login.Username, login.Password);
            if (isValid)
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_secretKey);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, login.Username),
                        new Claim(ClaimTypes.Role, role)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                _cache.Remove(cacheKey); // Reset login attempts on successful login
                return Ok(new { Token = tokenString });
            }

            // Increment login attempts
            _cache.Set(cacheKey, attempts + 1, TimeSpan.FromMinutes(15));
            return Unauthorized();
        }

        [HttpPost("insecure-register")]
        public async Task<IActionResult> InsecureRegister([FromBody] RegisterModel register)
        {
            var result = await _userService.RegisterUserInsecureAsync(register.Username, register.Password, "User");
            if (result)
            {
                return Ok();
            }

            return BadRequest("User registration failed");
        }

        [HttpPost("secure-register")]
        public async Task<IActionResult> SecureRegister([FromBody] RegisterModel register)
        {
            var (isValid, errorMessage) = PasswordPolicy.ValidatePassword(register.Password);
            if (!isValid)
            {
                return BadRequest(errorMessage);
            }

            var result = await _userService.RegisterUserSecureAsync(register.Username, register.Password, "User");
            if (result)
            {
                return Ok();
            }

            return BadRequest("User registration failed");
        }

        [Authorize]
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", string.Empty);
            TokenBlacklist.Add(token);
            return Ok();
        }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
