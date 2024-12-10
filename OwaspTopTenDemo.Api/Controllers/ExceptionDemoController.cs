// File: OwaspTopTenDemo.Api/Controllers/ExceptionDemoController.cs
using Microsoft.AspNetCore.Mvc;

namespace OwaspTopTenDemo.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ExceptionDemoController : ControllerBase
    {
        [HttpGet("throw")]
        public IActionResult ThrowException()
        {

                // Simulate an error
                throw new Exception($"Test exception with sensitive info");

        }
    }
}

