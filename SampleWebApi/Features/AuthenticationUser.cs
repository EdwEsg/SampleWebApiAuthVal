using SampleWebApi.Common;
using MediatR;
using Microsoft.IdentityModel.Tokens;
using SampleWebApi.Data;
using SampleWebApi.Domain;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using static SampleWebApi.Features.AuthenticationUser;

namespace SampleWebApi.Features
{
    [Route("api/Authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IMediator _mediator;

        public AuthenticationController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost("UserAuthentication")]
        public async Task<IActionResult> AuthenticateUser([FromBody] AuthenticationUserCommand command)
        {
            try
            {
                var result = await _mediator.Send(command);
                if (result.IsFailure)
                {
                    return BadRequest(result);
                }
                return Ok(result);
            }
            catch (Exception ex)
            {
                return Conflict(ex.Message);
            }
        }
    }


    public class AuthenticationUser
    {

        public class AuthenticationUserResult
        {
            public int Id { get; set; }

            public string FullName { get; set; }

            public string UserName { get; set; }

            public string Password { get; set; }

            public string Token { get; set; }

            public AuthenticationUserResult(User user, string jwtToken)
            {
                
                Id = user.Id;
                FullName = user.Fullname;
                UserName = user.Username; 
                Password = user.Password;
                Token = jwtToken;

            }
        }

        public class AuthenticationUserCommand : IRequest<Result>
        {
            [Required]
            public string Username { get; set; }
            [Required]
            public string Password { get; set; }
        }



        public class Handler : IRequestHandler<AuthenticationUserCommand, Result>
        {

            private readonly IConfiguration _configuration;
            private readonly SampleWebApiDbContext _context;

            public Handler(SampleWebApiDbContext context , IConfiguration configuration)
            {
                _context = context;
                _configuration = configuration;
            }

            public async Task<Result> Handle(AuthenticationUserCommand command, CancellationToken cancellationToken)
            {

                var user =  _context.Users.Where(x => x.Username == command.Username && x.Password == command.Password && x.IsActive == true)
                    .SingleOrDefault();

                if(user == null)
                {
                    return Result.Failure(UserErrors.IncorrectUsernameOrPassword());
                }


                await _context.SaveChangesAsync(cancellationToken);

                var jwtToken = CreateToken(user);

                var result = user.ToGetAuthenticatedUserResult(jwtToken);

                return Result.Success(result);


            }

            public string CreateToken(User user)
            {
                var tokenKey = _configuration.GetValue<string>("AppSettings:Token");
                var encoding = Encoding.ASCII.GetBytes(tokenKey);
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim("id", user.Id.ToString()),
                        new Claim(ClaimTypes.Name , user.Fullname),
                    }),
                    Expires = DateTime.Now.AddDays(1),
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(encoding),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var jwtToken = tokenHandler.CreateToken(tokenDescriptor);
                return tokenHandler.WriteToken(jwtToken);
            }


        }


    }

    public static class AuthenticateMappingExtension
    {
        public static AuthenticationUser.AuthenticationUserResult ToGetAuthenticatedUserResult(this User user, string token)
        {
            return new AuthenticationUser.AuthenticationUserResult(user, token);
        }

    }
}
