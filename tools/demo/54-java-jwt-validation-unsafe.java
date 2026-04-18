import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletRequest;

public class JwtReaderUnsafe {
    public void parse(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        DecodedJWT decoded = JWT.decode(token);
    }
}
