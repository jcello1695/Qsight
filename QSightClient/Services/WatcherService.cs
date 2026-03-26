using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace QSightClient.Services
{
	public class WatcherService
	{
		private FileSystemWatcher? _watcher;
		private readonly ApiService _api;

		public event Action<string>? OnFileDetected;

		public WatcherService(ApiService api)
		{
			_api = api;
		}

		public void StartWatching()
		{
			var downloadsPath = Path.Combine(
				Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
				"Downloads"
			);

			_watcher = new FileSystemWatcher(downloadsPath)
			{
				NotifyFilter = NotifyFilters.FileName,
				Filter = "*.*",
				EnableRaisingEvents = true
			};

			_watcher.Created += OnFileCreated;
		}

		public void StopWatching()
		{
			if (_watcher != null)
			{
				_watcher.EnableRaisingEvents = false;
				_watcher.Dispose();
				_watcher = null;
			}
		}

		private async void OnFileCreated(object sender, FileSystemEventArgs e)
		{
			// 파일 쓰기 완료 대기 (다운로드 중 감지 방지)
			await Task.Delay(2000);

			if (!File.Exists(e.FullPath)) return;

			OnFileDetected?.Invoke(e.Name ?? e.FullPath);

			try
			{
                await App.Agent.StartHeadlessScan(e.FullPath);
			}
			catch
			{
				// 파일 접근 실패 등 무시
			}
		}
	}
}