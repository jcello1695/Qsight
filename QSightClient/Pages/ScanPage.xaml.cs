using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using QSightClient.Models;
using System;
using System.IO;
using System.Security.Cryptography;
using Windows.Storage.Pickers;

namespace QSightClient.Pages
{
    public sealed partial class ScanPage : Page
    {
        private string? _selectedFilePath;
        private ScanLog _selectedLog = new();

        public ScanPage()
        {
            InitializeComponent();
            this.NavigationCacheMode = NavigationCacheMode.Enabled;
        }

        private async void SelectFile_Click(object sender, RoutedEventArgs e)
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");

            // WinUI3 requires window handle
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.MainWindow);
            WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);

            var file = await picker.PickSingleFileAsync();
            if (file == null) return;

            _selectedFilePath = file.Path;
            SelectedFileText.Text = file.Name;
            StartScanButton.IsEnabled = true;
            RegistWhiteListButton.IsEnabled = false;

            ScanStatusText.Text = "-";
            ScanSeverityText.Text = "-";
            StaticResultText.Text = "-";
            ScanIdText.Text = "-";
        }

        private async void StartScan_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedFilePath == null) return;

            StartScanButton.IsEnabled = false;
            SelectFileButton.IsEnabled = false;
            ScanStatusText.Text = "분석 중 version2";

            try
            {
                var log = await App.Agent.StartHeadlessScan(_selectedFilePath);

                if (log == null) return;

                _selectedLog = log;
                ScanStatusText.Text = $"완료: { log.StaticResult}";
            }
            catch (Exception ex)
            {
                ScanStatusText.Text = $"오류: {ex.Message}";
            }
            finally
            {
                if(_selectedLog.StaticResult == "whitelisted")
                    RegistWhiteListButton.IsEnabled = false;
                else
                    RegistWhiteListButton.IsEnabled = true;
                
                SelectFileButton.IsEnabled = true;
            }
        }

        private void OnWhitelist_Click(object sender, RoutedEventArgs e)
        {
            if (_selectedLog == null)
                return;

            App.WhiteList.Add(_selectedLog.FileName, _selectedLog.Sha256);
            RegistWhiteListButton.IsEnabled = false;

            // 사용자 피드백
            ScanStatusText.Text = "화이트리스트에 등록되었습니다.";
        }
    }
}