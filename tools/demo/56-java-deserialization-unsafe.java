import jakarta.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;

public class ObjectLoaderUnsafe {
    public void load(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        Object value = in.readObject();
    }
}
