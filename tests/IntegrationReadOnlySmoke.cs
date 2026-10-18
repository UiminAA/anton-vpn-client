using System;
using System.Security.Principal;
using System.Text.RegularExpressions;
namespace AntonVpn {
    internal static class IntegrationReadOnlySmoke {
        private static int Main() {
            WindowsIntegration.ValidateInstallPath();
            WindowsIntegration.ValidateOwnerSid(WindowsIdentity.GetCurrent().User.Value);
            bool rejected = false;
            try { WindowsIntegration.ValidateOwnerSid("S-1-0-0"); } catch (InvalidOperationException) { rejected = true; }
            if (!rejected) throw new Exception("Other-account elevation must be rejected.");
            if (!Regex.IsMatch(WindowsIntegration.TaskName(), "^v2rayNAutoRun_[0-9a-f]{32}$")) throw new Exception("Unexpected task identifier.");
            WindowsIntegration.CaptureIntegration();
            dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            service.Connect();
            dynamic definition = service.NewTask(0);
            definition.Principal.UserId = WindowsIdentity.GetCurrent().User.Value;
            dynamic action = definition.Actions.Create(0);
            action.Path = System.IO.Path.Combine(Support.ClientDir, "v2rayN.exe");
            var wrapper = new TaskWrapper { Definition = definition };
            var validate = typeof(WindowsIntegration).GetMethod("AssertOurTask", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
            validate.Invoke(null, new object[] { wrapper });
            Console.WriteLine("INTEGRATION_READ_ONLY_OK");
            return 0;
        }
    }
    internal sealed class TaskWrapper { public object Definition { get; set; } }
}
