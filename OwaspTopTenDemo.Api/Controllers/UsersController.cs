using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OwaspTopTenDemo.Api.Services;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace OwaspTopTenDemo.Api.Controllers
{
    [ApiController]
    [Authorize]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserService _userService;
        private readonly HtmlEncodingService _htmlEncodingService;
        private readonly ILogger<UsersController> _logger;

        public UsersController(UserService userService, HtmlEncodingService htmlEncodingService, ILogger<UsersController> logger)
        {
            _userService = userService;
            _htmlEncodingService = htmlEncodingService;
            _logger = logger;
        }

        // Vulnerable SQL Injection Endpoint
        [HttpGet("vulnerable-sql")]
        public async Task<IActionResult> GetVulnerableSql([FromQuery] string userInput)
        {
            _logger.LogInformation("Received request for vulnerable-sql with userInput: {UserInput}", userInput);
            var result = await _userService.GetUserByNameAsync(userInput);
            return Ok(result);
        }

        // Secure SQL Injection Endpoint
        [HttpGet("secure-sql")]
        public async Task<IActionResult> GetSecureSql([FromQuery] string userInput)
        {
            _logger.LogInformation("Received request for secure-sql with userInput: {UserInput}", userInput);
            var result = await _userService.GetUserByNameSecureAsync(userInput);
            return Ok(result);
        }

        // Vulnerable XSS Endpoint
        [HttpGet("vulnerable-xss")]
        public IActionResult GetVulnerableXss([FromQuery] string userInput)
        {
            _logger.LogInformation("Received request for vulnerable-xss with userInput: {UserInput}", userInput);
            var response = $"<html><body><h1>Hello, {userInput}</h1></body></html>";
            Response.Headers.Add("X-XSS-Protection", "0");
            return Content(response, "text/html");
        }

        // Secure XSS Endpoint
        [HttpGet("secure-xss")]
        public IActionResult GetSecureXss([FromQuery] string userInput)
        {
            _logger.LogInformation("Received request for secure-xss with userInput: {UserInput}", userInput);
            var response = $"<html><body><h1>Hello, {_htmlEncodingService.Encode(userInput)}</h1></body></html>";
            return Content(response, "text/html");
        }

        // Vulnerable Admin Endpoint
        [HttpGet("vulnerable-admin")]
        public async Task<IActionResult> GetVulnerableAdminData()
        {
            _logger.LogInformation("Received request for vulnerable-admin");
            var result = await _userService.GetSensitiveDataAsync();
            return Ok(result);
        }

        // Secure Admin Endpoint
        [HttpGet("secure-admin")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetSecureAdminData()
        {
            _logger.LogInformation("Received request for secure-admin");
            var result = await _userService.GetSensitiveDataAsync();
            return Ok(result);
        }
    }
}
