using QSightClient.Models;
using QSightClient.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.IO;

namespace QSightClient.Services
{
    public class AgentService
    {
        private readonly ScanEngine _engine = new();
        private readonly ConcurrentQueue<ScanRequest> _queue = new();
        private bool _isProcessing = false;
        public event Action<string>? OnScanStarted;
        public event Action<string, string>? OnScanCompleted; // fileName, result
        public event Action<string>? OnScanStatusChanged;
        public event Action<int>? OnScanProgressChanged;
        public event Action<List<string>>? OnQueueChanged;

        public AgentService()
        {
            _engine.OnStatusChanged += s =>
            {
                OnScanStatusChanged?.Invoke(s);
            };

            _engine.OnProgressChanged += p =>
            {
                OnScanProgressChanged?.Invoke(p);
            };
        }

        public void HandleIPC(IPCMessage msg)
        {
            if (msg.Command == "SCAN")
            {
                _queue.Enqueue(new ScanRequest { Path = msg.Path });
                NotifyQueue();

                _ = Task.Run(async () => await ProcessQueueAsync());
            }
        }

        public async Task<ScanLog?> StartHeadlessScan(string path)
        {
            OnScanStarted?.Invoke(path);
            var log = await _engine.StartScan(path);

            if(log != null)
                OnScanCompleted?.Invoke(Path.GetFileName(path), log.StaticResult);

            return log;
        }

        private void NotifyQueue()
        {
            var currentQueueItems = _queue.ToArray().Select(q => q.Path).ToList();
            OnQueueChanged?.Invoke(currentQueueItems);
        }

        private async Task ProcessQueueAsync()
        {
            if (_isProcessing) return;
            _isProcessing = true;

            try
            {
                while (_queue.TryDequeue(out var req))
                {
                    NotifyQueue();
                    OnScanStarted?.Invoke(req.Path);

                    var log = await _engine.StartScan(req.Path);

                    if (log != null)
                    {
                        OnScanCompleted?.Invoke(Path.GetFileName(req.Path), log.StaticResult);
                    }
                }
            }
            finally
            {
                _isProcessing = false;
            }
        }

        public void CancelScan()
        {
            _engine.CancelScan();
        }
    }
}