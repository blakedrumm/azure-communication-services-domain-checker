# ===== Graceful Shutdown =====
finally {
# ------------------- GRACEFUL SHUTDOWN -------------------
# Stop listeners, persist final metrics, drain in-flight requests, and dispose the pool.
try { if ($listener -and $listener.IsListening) { $listener.Stop() } } catch { $null = $_ }
try { if ($tcpListener) { $tcpListener.Stop() } } catch { $null = $_ }

  # Persist metrics one last time.
  try { Save-AnonymousMetricsPersisted -Force } catch { $null = $_ }

  Invoke-InflightCleanup
  foreach ($invocationId in @($inflight.Keys)) {
    Complete-InflightInvocation -InvocationId $invocationId -Force
  }
  try { $pool.Close(); $pool.Dispose() } catch { $null = $_ }
  Write-Information -InformationAction Continue -MessageData "Server stopped."
}
