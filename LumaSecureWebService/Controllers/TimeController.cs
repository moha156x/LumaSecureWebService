using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LumaSecureWebService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TimeController : Controller
    {
        [HttpGet]
        public IActionResult GetUTCTime()
        {
            return Ok(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff"));
        }
    }
}
