using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace LumaSecureWebService.Controllers
{
    [Route("api/[controller]/file")]
    [ApiController]
    public class UploadController : Controller
    {
        private readonly IConfiguration _config;
        private readonly ILogger<UploadController> _logger;
        public UploadController(IConfiguration config, ILogger<UploadController> logger)
        {
            _config = config;
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Get()
        {
            return Ok(new { Message = "please use api/upload with POST verb to upload a file" });
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> PostFile(IFormFile file)
        {
            try
            {
                if (file == null || file.Length == 0)
                {
                    _logger.LogError("No file is provided");
                    return BadRequest(new { Message = "File is not provided or is empty." });
                }

                //check for zip file type
                //only works for binary file
                //binary file that been encoded in base64 will not work
                //if want to implent for base64 it will complicate the api and prone to error
                //if (file.ContentType != "application/zip")
                //{
                //    _logger.LogError("Upload : Invalid file type.");
                //    return BadRequest(new { Message = "Only ZIP file are allowed." });
                //}

                string root = _config.GetValue<string>("UploadSettings:UploadPath");
                if (!Directory.Exists(root))
                {
                    Directory.CreateDirectory(root);
                }

                await CopyFile(root, file);

                return Ok(new { Message = $"Uploaded file: {file.FileName} ({file.Length} bytes)" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Upload : An error occur while processing the request.");
                return StatusCode(500, "Internal server error, please try again later.");
            }
        }

        private async Task CopyFile(string root, IFormFile file)
        {
            var filePath = Path.Combine(root, file.FileName);
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(fileStream);
            }
        }
    }
}
