using MediatR;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SampleWebApi.Common;
using SampleWebApi.Data;

namespace SampleWebApi.Features
{
    [Route("api/User"), ApiController]
    public class UpdateUser : ControllerBase
    {
        private readonly IMediator _mediator;

        public UpdateUser(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPut("UpdateUser/{id}")]
        public async Task<IActionResult> Update([FromBody] UpdateUserCommand command, [FromRoute]int id)
        {
            try
            {
                command.UserId = id;
                var result = await _mediator.Send(command);
                if (result.IsFailure)
                {
                    return BadRequest(result);
                }
                return Ok (result);
            }
            catch(Exception ex) 
            {
                return BadRequest(ex.Message);
            }
        }
        public class UpdateUserCommand : IRequest<Result>
        {
            public int UserId { get; set; }
            public string Fullame { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
        }

        public class UpdateUserResult
        {
            public int Id { get; set; }
            public string Fullame { get; set; }
            public string UserName { get; set; }
            public string Password { get; set; }
        }

        public class Handler : IRequestHandler<UpdateUserCommand, Result>
        {
            private readonly SampleWebApiDbContext _context;

            public Handler(SampleWebApiDbContext context)
            {
                _context = context;
            }

            public async Task<Result> Handle(UpdateUserCommand command, CancellationToken cancellationToken)
            {
                var existingUser = await _context.Users
                    .FirstOrDefaultAsync(user => user.Id == command.UserId, cancellationToken);

                if (existingUser is null) 
                {
                    return Result<UpdateUserResult>.Failure(UserErrors.NotFound());
                }

                existingUser.Fullname = command.Fullame;
                existingUser.Username = command.Username;
                existingUser.Password = command.Password;   

                await _context.SaveChangesAsync(cancellationToken);

                var result = new UpdateUserResult
                {
                    Id = existingUser.Id,
                    Fullame = existingUser.Fullname,
                    UserName = existingUser.Username,
                    Password = existingUser.Password,
                };

                return Result.Success();

            }
        }
    }
}
