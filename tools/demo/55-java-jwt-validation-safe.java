import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.http.HttpServletRequest;

public class JwtReaderSafe {
    public void parse(HttpServletRequest request, String secret) {
        String token = request.getHeader("Authorization");
        JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
    }
}
