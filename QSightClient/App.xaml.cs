using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using QSightClient.Services;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;

namespace QSightClient
{
    public partial class App : Application
    {
        public static IPCService IPC { get; } = new();
        public static AgentService Agent { get; } = new();
        public static LogService Logs { get; } = new();
        public static ApiService Api { get; } = new();
        public static WatcherService Watcher { get; } = new(Api);
        public static WhiteListService WhiteList { get; set; } = new();

        public App()
        {
            InitializeComponent();
        }

        public static Window? MainWindow { get; private set; }

        protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
        {
            IPC.OnMessageReceived += Agent.HandleIPC;

            if(args.Arguments.Contains("--headless"))
            {
                RunHeadless(args.Arguments);
                return;
            }

            MainWindow = new MainWindow();
            MainWindow.Activate();
            Logs.LoadFromDisk();

            Watcher.OnFileDetected += fileName =>
            {
                Debug.WriteLine($"새 파일 감지: {fileName}");
            };

            Agent.OnScanCompleted += (fileName, result) =>
            {
                Debug.WriteLine($"스캔 완료: {fileName} → {result}");
            };

            Watcher.StartWatching();

            _ = Task.Run(async () =>
            {
                var ok = await Api.HealthCheckAsync();
                Debug.WriteLine($"[API] Server health: {ok}");
            });
        }

        private async void RunHeadless(string arguments)
        {
            var parts = arguments.Split("--scan");

            if(parts.Length > 1)
            {
                var path = parts[1].Trim().Trim('"');

                await Agent.StartHeadlessScan(path);
            }

            Environment.Exit(0);
        }
    }
}

