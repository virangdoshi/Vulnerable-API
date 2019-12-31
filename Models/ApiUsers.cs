
namespace VulnAPI.Models
{
    public partial class ApiUsers
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Pass { get; set; }
        public long? Mobile { get; set; }
        public string Company { get; set; }

        public string level_priv {get; set;}

        public int? acc_id { get; set; }
        
    }
}
