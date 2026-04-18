import jakarta.servlet.http.HttpServletRequest;
import java.net.URL;

public class AvatarFetcherUnsafe {
    public void fetch(HttpServletRequest request) throws Exception {
        String url = request.getParameter("url");
        URL target = new URL(url);
        target.openStream();
    }
}
