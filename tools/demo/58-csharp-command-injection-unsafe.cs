using System.Diagnostics;

public class CommandRunnerUnsafe
{
    public void Run()
    {
        string cmd = Request.Query["cmd"];
        Process.Start(cmd);
    }
}
