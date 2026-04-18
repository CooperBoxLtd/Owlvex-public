import jakarta.servlet.http.HttpServletRequest;

public class CommandRunnerUnsafe {
    public void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
