using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Serilog;
using System.Web;
using System.Net;
using Microsoft.Owin.BuilderProperties;

namespace LumaSecureWebService.Controllers
{
    public class SecurityTokenValidator : ISecurityTokenValidator
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly ILogger<SecurityTokenValidator> _logger;
        public SecurityTokenValidator(IHttpContextAccessor httpContextAccessor, ILogger<SecurityTokenValidator> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _tokenHandler = new JwtSecurityTokenHandler();
            _logger = logger;
        }

        public bool CanValidateToken => true;
        public int MaximumTokenSizeInBytes { get; set; } = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
        public bool CanReadToken(string securityToken)
        {
            return _tokenHandler.CanReadToken(securityToken);
        }

        public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validateToken)
        {
            try
            {
                //validate token as usual
                var principal = _tokenHandler.ValidateToken(securityToken, validationParameters, out validateToken);

                //get requestor ip address via header
                var ipAddress = _httpContextAccessor.HttpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
                var tokenIpAddressClaim = principal.Claims.FirstOrDefault(c => c.Type == "ip");
                var tokenIpAddress = tokenIpAddressClaim?.Value;

                //_httpContextAccessor.HttpContext.Connection.RemoteIpAddress.ToString();
                if (ipAddress == null || tokenIpAddress==null)
                {
                    _logger.LogError("Null Ip Address");
                    throw new SecurityTokenValidationException("Invalid request Ip address");
                }

                if (!ValidateIp(ipAddress) || !ValidateIp(tokenIpAddress))
                {
                    _logger.LogError("Invalid Ip Address format in X-Forwarded-For header.");
                    throw new SecurityTokenValidationException("Invalid request Ip address");
                }

                //if ip address not match
                if (!CompareIpAddress(tokenIpAddress, ipAddress))
                {
                    _logger.LogError($"Client IP address {ipAddress} mismatch with token Ip Address {tokenIpAddress}");
                    throw new SecurityTokenValidationException("Invalid token");
                }

                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,"An error occured while validationg the token");
                throw;
            }
        }

        private bool CompareIpAddress(string tokenIpAddress, string ipAddress)
        {
            _logger.LogInformation($"Requestor IP: {ipAddress}");
            _logger.LogInformation($"Token IP: {tokenIpAddress}");

            //if ip address not match
            if (ipAddress != tokenIpAddress)
            {
                return false;
            }
            return true;
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
