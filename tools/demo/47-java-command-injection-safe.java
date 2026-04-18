import jakarta.servlet.http.HttpServletRequest;

public class CommandRunnerSafe {
    public void run(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        new ProcessBuilder("grep", name).start();
    }
}
