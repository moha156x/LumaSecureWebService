using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace LumaSecureWebService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : Controller
    {
        private readonly IConfiguration _config;
        private readonly ILogger<TokenController> _logger;

        public TokenController(IConfiguration config, ILogger<TokenController> logger)
        {
            _config = config;
            _logger = logger;
        }

        [HttpGet("GetAuthToken")]
        public IActionResult GetAuthToken()
        {
            try
            {
                //var remoteIpAddress = HttpContext.Connection.RemoteIpAddress;

                string headerValue = HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
                var remoteIpAddress = IPAddress.Parse(headerValue);
                //var remoteIpAddress = string.IsNullOrEmpty(headerValue)
                //    ? HttpContext.Connection.RemoteIpAddress
                //    : IPAddress.Parse(headerValue.Split(',').FirstOrDefault());

                _logger.LogInformation($"Get Remote Ip Address for token: {remoteIpAddress}");
                //_logger.LogInformation($"Get header value : {headerValue}");

                if(!ValidateIp(headerValue))
                {
                    _logger.LogError("Invalid Ip Address format in X-Forwarded-For header.");
                    return BadRequest(new { Message = "Invalid Ip Address" });
                }

                if (remoteIpAddress == null)
                {
                    _logger.LogError("Failed to determine remote Ip Address");
                    return Unauthorized();
                }

                //bool isKnownSubnet = IsSubnetValid(remoteIpAddress);

                if (!IsSubnetValid(remoteIpAddress))
                {
                    _logger.LogError($"GetAuthToken: The Ip Address {remoteIpAddress} is not authotized to request token");
                    return Unauthorized($"The IP address {remoteIpAddress} is not authorized to request a token.");
                }

                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, _config["Jwt:Issuer"]),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("ip", remoteIpAddress.ToString())
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                int expires = _config.GetValue<int>("Jwt:Expires");

                var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                    _config["Jwt:Issuer"],
                    claims,
                    expires: DateTime.UtcNow.AddMinutes(expires),
                    signingCredentials: creds);

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetAuthToken: An error occur while processing the request.");
                return StatusCode(500, "Internal server error, please try again later.");
            }

        }

        private bool IsSubnetValid(IPAddress remoteIpAddress)
        {
            var knownSubnets = _config.GetSection("UploadSettings:AllowedSubnets").Get<List<string>>();
            
            foreach (var subnet in knownSubnets)
            {
                var ipNetwork = System.Net.IPNetwork.Parse(subnet);
                if (System.Net.IPNetwork.Contains(ipNetwork, remoteIpAddress))
                {
                    return true;
                }
            }
            return false;
        }

        private bool ValidateIp(string headerValue)
        {
            if (!string.IsNullOrEmpty(headerValue))
            {
                IPAddress ip;
                if (!IPAddress.TryParse(headerValue, out ip))
                {
                    return false;
                }
            }
            return true;
        }
    }
}
