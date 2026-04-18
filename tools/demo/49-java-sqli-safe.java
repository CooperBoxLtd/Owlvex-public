import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;

public class UserLookupSafe {
    public void load(HttpServletRequest request, Connection conn) throws Exception {
        String userId = request.getParameter("id");
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
    }
}
