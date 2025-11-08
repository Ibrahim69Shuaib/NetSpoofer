using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Windows;

namespace NetSpoofer {
    public partial class App : Application {
        protected override void OnStartup(StartupEventArgs e) {
            base.OnStartup(e);
            if (!IsAdministrator()) {
                Elevate();
                Current.Shutdown();
                return;
            }
            EnsureNpcapInstalled();
        }

        private static bool IsAdministrator() {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void Elevate() {
            var exe = Process.GetCurrentProcess().MainModule!.FileName!;
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" };
            try { Process.Start(psi); } catch { }
        }

        private static void EnsureNpcapInstalled() {
            bool installed = ServiceController.GetServices().Any(s => s.ServiceName.Equals("npcap", StringComparison.OrdinalIgnoreCase));
            if (installed) return;
            var temp = Path.Combine(Path.GetTempPath(), "npcap-1.84.exe");
            try {
                using var s = Application.GetResourceStream(new Uri("pack://application:,,,/Resources/npcap-1.84.exe"))?.Stream;
                if (s == null) return;
                using var fs = File.Create(temp);
                s.CopyTo(fs);
                fs.Flush();
            } catch { return; }
            try {
                var psi = new ProcessStartInfo(temp, "/S") { UseShellExecute = true, Verb = "runas" };
                using var proc = Process.Start(psi);
                proc?.WaitForExit();
            } catch { }
        }
    }
}