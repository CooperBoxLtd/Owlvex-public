import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

public class ObjectLoaderSafe {
    public Profile load(HttpServletRequest request, ObjectMapper mapper) throws Exception {
        return mapper.readValue(request.getInputStream(), Profile.class);
    }
}

class Profile {
    public String name;
}
