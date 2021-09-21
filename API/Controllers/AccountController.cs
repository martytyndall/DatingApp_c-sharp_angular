using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    // The Account controller derives from the BaseApiController
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }


        [HttpPost("register")]
        // method for registering new user, including username and password.
        // uses set methods inside AppUser class
        // async task for interacting with DB
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {

            // conditional statement that calls the UserExists method which returns boolean value to the statement
            // if true (user exists), stement returns a bad request with message
            if (await UserExists(registerDto.Username)) return BadRequest("Username is taken");

            // calls the HMACSHA512 class to apply the hashing algorithm to the password
            using var hmac = new HMACSHA512();

            // creates a new instance of AppUser with passed in parameters, and stores in user variable
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                // takes password string and converts to byte array using encoding method
                // computes hashed password and stores in PasswordHash variable
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),

                // method to return the random key to use in the calculation, stores in PasswordSalt variable
                PasswordSalt = hmac.Key
            };

            // adds new user to database using entity framework
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users
                .SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

            if (user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var ComputedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < ComputedHash.Length; i++)
            {
                if (ComputedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }


        // helper method to check if user already exists in database
        private async Task<bool> UserExists(string username)
        {
            // interacts with database, so await is used
            // AnyAsync method checks asynchronously if the query satisfies the condition within the parenthesis
            // returns result
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}