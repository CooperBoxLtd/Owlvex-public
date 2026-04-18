using Microsoft.Data.SqlClient;

public class UserLookupUnsafe
{
    public void Load()
    {
        string userId = Request.Query["id"];
        string sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        var cmd = new SqlCommand(sql, conn);
    }
}
