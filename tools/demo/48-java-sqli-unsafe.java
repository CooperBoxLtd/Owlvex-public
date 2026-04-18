import jakarta.servlet.http.HttpServletRequest;
import java.sql.Statement;

public class UserLookupUnsafe {
    public void load(HttpServletRequest request, Statement stmt) throws Exception {
        String userId = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        stmt.executeQuery(sql);
    }
}
