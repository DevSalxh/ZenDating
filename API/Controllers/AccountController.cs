using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Extensions;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(AppDbContext context, ITokenService tokenService) : BaseApiController
{
    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register([FromBody] RegisterDto registerDto)
    {
        if (await DoesUserExist(registerDto.Email)) return BadRequest("this email has been taken");

        using var hmac = new HMACSHA256();
        var user = new AppUser()
        {
            DisplayName = registerDto.DisplayName,
            Email = registerDto.Email.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return user.ToDto(tokenService);
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login([FromBody] LoginDto loginDto)
    {
        var user = await context.Users.SingleOrDefaultAsync(u => u.Email.ToLower() == loginDto.Email.ToLower());
        if (user == null) return Unauthorized("Invalid Email!");

        using var hmac = new HMACSHA256(user.PasswordSalt);

        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password!");
        }
        return user.ToDto(tokenService);
    }

    private async Task<bool> DoesUserExist(string Email)
    {
        return await context.Users.AnyAsync(u => u.Email.ToLower() == Email.ToLower());
    }
}
