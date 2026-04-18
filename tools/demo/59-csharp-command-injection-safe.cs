using System.Diagnostics;

public class CommandRunnerSafe
{
    public void Run()
    {
        string name = Request.Query["name"];
        Process.Start("grep", name);
    }
}
