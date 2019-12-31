
using Microsoft.AspNetCore.Mvc;
using System;
using System.Text.Json;
using System.Collections.Generic;
using System.Data.SqlClient;
using VulnAPI.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;

namespace VulnAPI.Controllers
{
    
    [ApiController]
    public class ProfileController: ControllerBase
    {
        public ProfileController(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        private readonly IConfiguration Configuration;
        readonly Random rnd = new Random();

        [HttpGet]
        [Route("api/")]
        public string Welcome()
        {
            List<Object> resp = new List<Object>();

            resp.Add(new { Message = "This API has been created only for learning purpose and therefore deliberately has security vulnerabilities. " +
                "It has been created to demonstrate how APIs can have vulnerabilities and mostt of the issues are based on OWASP API Top 10 2019 project. "+
                "Happy Learning!. If you feel like to say something, contact me on https://www.infosecraj.com "
            });

            
            resp.Add(new { Endpoint = "api/User/Create", HTTP_method = "POST", purpose = "Create you account by providing email, pass, name, mobile and company." });
            resp.Add(new { Endpoint = "api/User/Login", HTTP_method = "POST", purpose = "Login to your account by providing email and pass to get auth token." });
            resp.Add(new { Endpoint = "api/User/View", HTTP_method = "GET", purpose = "View your account details by providing auth token as a header Authorization: Bearer <toke>" });
            resp.Add(new { Endpoint = "api/User/Delete", HTTP_method = "POST", purpose = "Delete your account by providing email Id and auth token as a header Authorization: Bearer <toke>" });
            resp.Add(new { Endpoint = "api/User/ForgotPasswd", HTTP_method = "POST", purpose = "If you forget your password, provide email ID to get OTP (you won't get any OTP. Just for name sake.)." });

            return JsonSerializer.Serialize(resp);
        }

        [HttpGet]
        [Authorize]
        [Route("api/Details/Users")]
        public string List()
        {
            var curretUser = HttpContext.User;
            string acc_id = Convert.ToString(curretUser.FindFirst("id").Value);
            string constr = Configuration.GetConnectionString("accountsDatabase");
            List<Object> users = new List<Object>();
            string? auth_type = null;
            string query1 = "SELECT Priv from api_users WHERE acc_id=@id";
            string query2 = "SELECT * from api_users";
            try
            {
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query1))
                    {
                        cmd.Parameters.AddWithValue("@id", acc_id);
                        cmd.Connection = con;
                        con.Open();
                        using (SqlDataReader sdr = cmd.ExecuteReader())
                        {

                            while (sdr.Read())
                            {
                                auth_type = Convert.ToString(sdr["Priv"]);
                            }
                            con.Close();
                        }
                    }
                    using (SqlCommand cmd = new SqlCommand(query2))
                    {
                        cmd.Connection = con;
                        con.Open();
                        using (SqlDataReader sdr = cmd.ExecuteReader())
                        {

                            while (sdr.Read())
                            {
                                if(auth_type != "Admin")
                                {
                                    users.Add(new ApiUsers
                                    {
                                        Name = Convert.ToString(sdr["Name"])

                                    });
                                }
                                else
                                {
                                    users.Add(new ApiUsers
                                    {
                                        Name = Convert.ToString(sdr["Name"]),
                                        Email = Convert.ToString(sdr["Email"]),
                                        Mobile = Convert.ToInt64(sdr["Mobile"]),
                                        Company = Convert.ToString(sdr["Company"]),
                                        level_priv = Convert.ToString(sdr["Priv"])
                                    });
                                }

                            }
                            con.Close();
                        }
                    }
                }
                if (users.Count == 0)
                {
                    return "Currently there are no users.";
                }
                else
                {
                    return JsonSerializer.Serialize(users);

                }
            }
            catch (Exception)
            {
                return "Some Error Occured While Listing Users.";
            }

        }

        [HttpGet]
        [Authorize]
        [Route("api/User/View")]
        public string Display()
        {
            var curretUser = HttpContext.User;
            string acc_id = Convert.ToString(curretUser.FindFirst("id").Value);
            List<Object> users = new List<Object>();
            string constr = Configuration.GetConnectionString("accountsDatabase");
            string query = "SELECT * from api_users WHERE acc_id=@acc_id";
            try
            {
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query))
                    {
                        cmd.Parameters.AddWithValue("@acc_id", acc_id);
                        cmd.Connection = con;
                        con.Open();
                        using (SqlDataReader sdr = cmd.ExecuteReader())
                        {
                            while (sdr.Read())
                            {
                                users.Add(new
                                {
                                    Name = Convert.ToString(sdr["Name"]),
                                    Email = Convert.ToString(sdr["Email"]),
                                    Mobile = Convert.ToInt32(sdr["Mobile"]),
                                    Company = Convert.ToString(sdr["Company"])

                                });
                            }
                            con.Close();
                        }
                    }
                }
                if (users.Count == 0)
                {
                    return "Invalid Token.";
                }
                else
                {
                    return JsonSerializer.Serialize(users);
                    
                }
            }
            catch (Exception)
            {
                return "Some Error Occured While retrieving details.";
            }
        }

        [HttpPost]
        [Route("api/User/Create")]
        public string Create(ApiUsers postdata)
        {
            List<Object> resp = new List<Object>();
            if (postdata.Email == null || postdata.Name == null || postdata.Pass == null)
            {
                return "Name and Email is mandatory and cannot be null. ";
            }

            else
            {
                if (postdata.Mobile == null) { postdata.Mobile = 0; }
                if (postdata.Company == null) { postdata.Company = "null"; }

                if (postdata.level_priv == null)
                {
                    postdata.level_priv = "user";
                }

                string constr = Configuration.GetConnectionString("accountsDatabase");
                string query = "INSERT INTO api_users(Name, Email, Pass, Mobile, Company, Priv, acc_id)" +
                               "VALUES (@name, @email, @pass, @mob, @company, @Priv, @Acc_id)";
                try
                {
                    using (SqlConnection con = new SqlConnection(constr))
                    {
                        using (SqlCommand cmd = new SqlCommand(query))
                        {
                            cmd.Parameters.AddWithValue("@name", postdata.Name);
                            cmd.Parameters.AddWithValue("@email", postdata.Email);
                            cmd.Parameters.AddWithValue("@pass", postdata.Pass);
                            cmd.Parameters.AddWithValue("@mob", postdata.Mobile);
                            cmd.Parameters.AddWithValue("@company", postdata.Company);
                            cmd.Parameters.AddWithValue("@Priv", postdata.level_priv);
                            cmd.Parameters.AddWithValue("@Acc_id", rnd.Next(11212, 999999));
                            cmd.Connection = con;
                            con.Open();
                            cmd.ExecuteScalar();
                            con.Close();
                        }
                    }
                    resp.Add(new { status = "success", message="Account Create successfully!." });
                    return JsonSerializer.Serialize(resp);
                }

                catch (SqlException ex)
                {
                    if (ex.Number == 2627)
                    {
                        resp.Add(new { status = "failure", message = "An account with provided email Id/Mobile number already exists. Please Login or use another email/Mobile" });
                        return JsonSerializer.Serialize(resp);
                    }
                    else
                    {
                        resp.Add(new { status = "failure", message = "An unknown error occured. Try again." });
                        return JsonSerializer.Serialize(resp);
                    }
                    
                }
            }
             
        }

        [HttpPost]
        [Route("api/User/Login")]
        public string Login(ApiUsers user)
        {
            List<Object> resp = new List<object>();
            if (user.Email == null || user.Pass == null)
            {
                resp.Add(new { status = "failure", message = "Email and Password is mandatory and cannot be null." });
                return JsonSerializer.Serialize(resp);
            }

            bool isAuthenticated = false;
            string constr = Configuration.GetConnectionString("accountsDatabase");
            string query = "SELECT acc_id,Priv from api_users WHERE Email=@email AND Pass=@pass";
            try
            {
            
                string? acc_id = null;
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query))
                    {
                        cmd.Parameters.AddWithValue("@email", user.Email);
                        cmd.Parameters.AddWithValue("@pass", user.Pass);
                        cmd.Connection = con;
                        con.Open();
                        using (SqlDataReader sdr = cmd.ExecuteReader())
                        {
                            if (sdr.HasRows)
                            {
                                isAuthenticated = true;
                                while(sdr.Read())
                                {
                                    acc_id= Convert.ToString(sdr["acc_id"]);
                                }

                            }
                            con.Close();
                        }
                    }
                }
                if (isAuthenticated)
                {
                    string skey = Configuration.GetValue<String>("JwtKey");
                    resp.Add(new { status = "success", token = new JWTToken().getToken(acc_id, skey) });
                    return JsonSerializer.Serialize(resp);
                }
                else
                {
                    resp.Add(new { status = "failure", message = "Invalid Email or Password." });
                    return JsonSerializer.Serialize(resp);
                }
            }
            catch (Exception)
            {
                resp.Add(new { status = "failure", message = "Some Unknown Error Occured While Logging in."});
                return JsonSerializer.Serialize(resp);

            }

        }

        [HttpPost]
        [Authorize]
        [Route("api/User/Delete")]
        public string Delete(ApiUsers user)
        {
            List<Object> resp = new List<object>();
            var curretUser = HttpContext.User;
            string acc_id = Convert.ToString(curretUser.FindFirst("id").Value);

            string constr = Configuration.GetConnectionString("accountsDatabase");
            string query = "DELETE FROM api_users WHERE Email=@email AND acc_id=@acc_id";
            try
            {
                int deleted = 0;
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query))
                    {
                        cmd.Parameters.AddWithValue("@email", user.Email);
                        cmd.Parameters.AddWithValue("@acc_id", acc_id);
                        cmd.Connection = con;
                        con.Open();
                        deleted = cmd.ExecuteNonQuery();
                        con.Close();
                    }
                }

                if(deleted != 0)
                {
                    resp.Add(new { status = "success", message = Convert.ToString(deleted) + " user account with email " + user.Email + " has been deleted." });
                    return JsonSerializer.Serialize(resp);
                }
                else
                {
                    resp.Add(new { status = "failure", message = Convert.ToString(deleted) + " Rows affected. " + user.Email + " does not exist or you are not authorized to delete this account" });
                    return JsonSerializer.Serialize(resp);
                }
                
            }
            catch (Exception)
            {
                resp.Add(new { status = "failure", message = "Some Error Occured While Deleting Account"});
                return JsonSerializer.Serialize(resp);
            }

        }

        [HttpPost]
        [Route("api/User/ForgotPasswd")]

        public string ForgotPass(ApiUsers user)
        {
            List<Object> resp = new List<object>();
            string constr = Configuration.GetConnectionString("accountsDatabase");
            string query = "SELECT acc_id FROM api_users WHERE Email=@email";
            try
            {
                string? acc_id = null;
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query))
                    {
                        cmd.Parameters.AddWithValue("@email", user.Email);
                        cmd.Connection = con;
                        con.Open();
                        using (SqlDataReader sdr = cmd.ExecuteReader())
                        {
                            while (sdr.Read())
                            {
                                acc_id = Convert.ToString(sdr["acc_id"]);
                            }
                            con.Close();
                        }
                    }
                }
                if(acc_id != null)
                {

                    resp.Add(new { status = "success", message = "OTP Sent successfully to registered mobile and email for account " + acc_id+
                        ". Enter OTP to Reset Password"});
                    return JsonSerializer.Serialize(resp);
                }
                else if(acc_id == null)
                {
                    resp.Add(new { status = "failure", message = "Provided email id doesn't exist in our records." });
                    return JsonSerializer.Serialize(resp);
                }
                else
                {
                    resp.Add(new { status = "failure", message = "Some unknown error occured." });
                    return JsonSerializer.Serialize(resp);
                }
            }
            catch (Exception)
            {
                resp.Add(new { status = "failure", message = "Some Error Occured While Creating Account." });
                return JsonSerializer.Serialize(resp);
            }

        }

        [HttpPost]
        [Route("api/User/ResetPass")]

        public string ResetPass(ApiUsers user)
        {
            List<Object> resp = new List<object>();
            string constr = Configuration.GetConnectionString("accountsDatabase");

            
            string query = "UPDATE api_users SET Pass=@Pass WHERE acc_id=@acc_id";
            try
            {
                int changed = 0;
                using (SqlConnection con = new SqlConnection(constr))
                {
                    using (SqlCommand cmd = new SqlCommand(query))
                    {
                        cmd.Parameters.AddWithValue("@Pass", user.Pass);
                        cmd.Parameters.AddWithValue("@acc_id", Convert.ToString(user.acc_id));
                        cmd.Connection = con;
                        con.Open();
                        changed = cmd.ExecuteNonQuery();
                        con.Close();
                    }
                }

                if (changed > 0)
                {
                    resp.Add(new { status = "success", message = "Password changed successfully. Login Again." });
                    return JsonSerializer.Serialize(resp);
                }
                else
                {
                    resp.Add(new { status = "failure", message = "Password was not changed. Check the input you have given and try again." });
                    return JsonSerializer.Serialize(resp);
                }
            }
            catch (Exception ex)
            {

                resp.Add(new { status = "failure", message = "Some Error Occured While Changing Password."+ex.Message});
                return JsonSerializer.Serialize(resp);
            }

        }        
    }
}
