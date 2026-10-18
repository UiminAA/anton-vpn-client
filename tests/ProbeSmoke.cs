using System;

namespace AntonVpn
{
    internal static class ProbeSmoke
    {
        private static int Main(string[] args)
        {
            if (args.Length != 1) { Console.WriteLine("PROBE_SMOKE_USAGE"); return 2; }
            try
            {
                // Personal connection material is accepted exclusively through standard input.
                string input = Console.In.ReadToEnd();
                VlessLink link = VlessLink.Parse(input);
                input = null;
                ConnectionProbe.Verify(args[0], link);
                Console.WriteLine("PROBE_SMOKE_OK");
                return 0;
            }
            catch (ArgumentException) { Console.WriteLine("PROBE_SMOKE_INVALID_LINK"); return 1; }
            catch { Console.WriteLine("PROBE_SMOKE_CONNECTION_FAILED"); return 1; }
        }
    }
}
