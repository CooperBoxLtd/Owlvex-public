using Microsoft.Data.SqlClient;

public class UserLookupSafe
{
    public void Load()
    {
        string userId = Request.Query["id"];
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", userId);
    }
}
