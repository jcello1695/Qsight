using System;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using QSightClient.Pages;
using QSightClient.Models;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Windows.Graphics;

namespace QSightClient
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            var hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            WindowId windowId = Win32Interop.GetWindowIdFromWindow(hWnd);
            AppWindow appWindow = AppWindow.GetFromWindowId(windowId);

            if (appWindow != null)
            {
                uint width = 800;
                uint height = 600;
                appWindow.Resize(new SizeInt32 { Width = (int)width, Height = (int)height });
            }

            this.Title = "Q-Sight Agent";
            RootNav.SelectionChanged += RootNav_SelectionChanged;
            ContentFrame.Navigate(typeof(StatusPage));

            ContentFrame.Navigated += (s, e) =>
            {
                var allowedPages = new[] { typeof(LogDetailPage) };

                RootNav.IsBackEnabled = allowedPages.Contains(e.SourcePageType) && ContentFrame.CanGoBack;
            };
        }

        private void RootNav_BackRequested(Microsoft.UI.Xaml.Controls.NavigationView sender, Microsoft.UI.Xaml.Controls.NavigationViewBackRequestedEventArgs args)
        {
            if (ContentFrame.CanGoBack)
            {
                ContentFrame.GoBack();
            }
        }

        private void RootNav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItemContainer is not NavigationViewItem item)
                return;

            switch (item.Tag)
            {
                case "status":
                    ContentFrame.Navigate(typeof(StatusPage));
                    break;

                case "scan":
                    ContentFrame.Navigate(typeof(ScanPage));
                    break;

                case "logs":
                    ContentFrame.Navigate(typeof(LogsPage));
                    break;

                case "about":
                    ContentFrame.Navigate(typeof(AboutPage));
                    break;
            }
        }
    }
}