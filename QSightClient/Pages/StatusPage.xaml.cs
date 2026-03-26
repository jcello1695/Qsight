using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;
using Microsoft.UI.Xaml.Shapes;
using QSightClient.Models;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace QSightClient.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class StatusPage : Page
    {
        public ObservableCollection<string> UnknownFiles { get; set; } = new();

        public StatusPage()
        {
            InitializeComponent();

            // WatcherService 이벤트 연결
            App.Watcher.OnFileDetected += fileName =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    CurrentFileText.Text = fileName;
                    LastMessageText.Text = $"File Detected: {fileName}";
                });
            };

            App.Agent.OnScanCompleted += (fileName, result) =>
            {
                DispatcherQueue.TryEnqueue(async () =>
                {
                    await LoadDashboardAsync();

                    if (result.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!UnknownFiles.Contains(fileName))
                            UnknownFiles.Add(fileName);
                    }
                });
            };

            App.Agent.OnScanStarted += path =>
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    CurrentFileText.Text = System.IO.Path.GetFileName(path);
                });
            };

            NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Required;

            App.IPC.OnMessageReceived += IPC_OnMessageReceived;
            App.Agent.OnScanStatusChanged += Agent_OnScanStatusChanged;
            App.Agent.OnScanProgressChanged += Agent_OnScanProgressChanged;
            App.Agent.OnQueueChanged += Agent_OnQueueChanged;

            _ = LoadDashboardAsync();
        }

        private void IPC_OnMessageReceived(IPCMessage msg)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                LastMessageText.Text = $"{msg.Command} : {msg.Path}";
            });
        }

        private void Agent_OnScanStatusChanged(string status)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                LastMessageText.Text = status;
            });
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            if (e.Parameter is IPCMessage msg)
            {
                CurrentFileText.Text = msg.Path;
            }
        }

        private void Agent_OnScanProgressChanged(int progress)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                ScanProgressBar.Value = progress;
            });
        }

        private void Agent_OnQueueChanged(List<string> queue)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                QueueList.ItemsSource = queue;
            });
        }

        private void CancelScan_Click(object sender, RoutedEventArgs e)
        {
            App.Agent.CancelScan();
        }
        private async void RefreshDashboard_Click(object sender, RoutedEventArgs e)
        {
            RefreshButton.IsEnabled = false;
            ServerStatusText.Text = "확인 중...";
            TotalScansText.Text = "-";
            HighSeverityText.Text = "-";
            CriticalSeverityText.Text = "-";

            await LoadDashboardAsync();

            RefreshButton.IsEnabled = true;
        }

        private async System.Threading.Tasks.Task LoadDashboardAsync()
        {
            var ok = await App.Api.HealthCheckAsync();
            ServerStatusText.Text = ok ? "연결됨" : "연결 실패";

            if (!ok) return;

            var summary = await App.Api.GetDashboardSummaryAsync(30);

            if (summary?.summary != null)
            {
                TotalScansText.Text = summary.summary.total_scans.ToString();
                HighSeverityText.Text = summary.summary.severity_high_count.ToString();
                CriticalSeverityText.Text = summary.summary.severity_critical_count.ToString();
            }
        }
    }
}
