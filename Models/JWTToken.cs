using System;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace VulnAPI.Models
{
    public class JWTToken
    {
        public JWTToken() { }

        public string getToken(string acc_id, string key)
        {
            var skey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));

            var authClaims = new[]
                {
                    new Claim("id", acc_id),
                };

            var token = new JwtSecurityToken(
                issuer: "DotNet Core 3.0",
                audience: "World",
                claims: authClaims,
                notBefore: DateTime.Now,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: new SigningCredentials(skey,SecurityAlgorithms.HmacSha256));

            string jwToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwToken;
        }

    }
}
