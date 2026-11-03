using DllSidecar.Core.Models;

namespace DllSidecar.Core.Services;

/// <summary>Bounded state for start/end events. Never infers an operation result from disk state.</summary>
internal sealed class EtwOperationCorrelator(int capacity = 16384)
{
    private readonly Dictionary<ulong, EtwTraceEvent> _pending = [];
    private readonly object _gate = new();
    public int Uncompleted { get; private set; }

    public void Begin(ulong irp, EtwTraceEvent ev)
    {
        lock (_gate)
        {
            if (irp == 0) { Uncompleted++; return; }
            // IRPs may be reused after a dropped completion. Do not join across that boundary.
            if (_pending.Remove(irp)) Uncompleted++;
            if (_pending.Count >= capacity)
            {
                var oldest = _pending.MinBy(p => p.Value.Timestamp).Key;
                _pending.Remove(oldest);
                Uncompleted++;
            }
            _pending[irp] = ev;
        }
    }

    public EtwTraceEvent? Complete(ulong irp, uint status, DateTime timestamp)
    {
        lock (_gate)
        {
            if (!_pending.TryGetValue(irp, out var ev) || timestamp < ev.Timestamp) return null;
            _pending.Remove(irp);
            ev.NtStatus = status;
            ev.CompletedAt = timestamp;
            return ev;
        }
    }

    public int Finish()
    {
        lock (_gate)
        {
            Uncompleted += _pending.Count;
            _pending.Clear();
            return Uncompleted;
        }
    }
}
