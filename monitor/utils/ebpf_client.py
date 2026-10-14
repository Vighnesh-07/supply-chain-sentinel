"""
Supply Chain Sentinel -- eBPF Agent HTTP Client
================================================
Lightweight client for the sentinel-agent REST API.
Used when the eBPF agent runs as a separate container
(docker compose --profile ebpf up).
"""
import requests
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

DEFAULT_AGENT_URL = "http://localhost:7777"


class EBPFAgentClient:
    """
    HTTP client for the sentinel-agent FastAPI server.

    The agent runs as a privileged Docker sidecar on Linux, so this client
    is intentionally thin -- it just wraps requests and lets the agent do
    all the heavy lifting (BCC, kprobes, perf buffers).
    """

    def __init__(self, base_url: str = DEFAULT_AGENT_URL, timeout: int = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Health / metadata
    # ------------------------------------------------------------------

    def health(self) -> Optional[Dict]:
        """
        Check agent health.

        Returns the health dict from /health, or None if the agent is
        unreachable or returns a non-200 response.
        """
        try:
            r = requests.get(f"{self.base_url}/health", timeout=self.timeout)
            return r.json() if r.ok else None
        except Exception:
            return None

    def capabilities(self) -> Optional[Dict]:
        """Return full capabilities dict from /capabilities."""
        try:
            r = requests.get(f"{self.base_url}/capabilities", timeout=self.timeout)
            return r.json() if r.ok else None
        except Exception:
            return None

    def is_available(self) -> bool:
        """Quick check -- returns True if the agent is running and healthy."""
        return self.health() is not None

    # ------------------------------------------------------------------
    # Monitoring lifecycle
    # ------------------------------------------------------------------

    def start_monitoring(
        self,
        container_ids: List[str],
        log_file: Optional[str] = None,
    ) -> bool:
        """
        Start eBPF monitoring for the given containers.

        Args:
            container_ids: Docker container names or IDs to monitor.
            log_file:      Optional path inside the agent container for
                           event log output.

        Returns:
            True if the agent accepted the request, False otherwise.
        """
        try:
            payload: Dict = {"container_ids": container_ids}
            if log_file:
                payload["log_file"] = log_file
            r = requests.post(
                f"{self.base_url}/monitor/start",
                json=payload,
                timeout=self.timeout,
            )
            return r.ok
        except Exception:
            return False

    def stop_monitoring(self) -> Dict:
        """
        Stop monitoring and return an event summary dict.

        Returns an empty dict if the agent is unreachable.
        """
        try:
            r = requests.post(f"{self.base_url}/monitor/stop", timeout=self.timeout)
            return r.json() if r.ok else {}
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Event retrieval
    # ------------------------------------------------------------------

    def get_events(
        self,
        since: Optional[float] = None,
        min_severity: Optional[str] = None,
    ) -> List[Dict]:
        """
        Fetch captured events from the agent buffer.

        Args:
            since:        Unix timestamp; only return events after this time.
            min_severity: Minimum severity to include: LOW|MEDIUM|HIGH|CRITICAL.

        Returns:
            List of event dicts, or an empty list on failure.
        """
        params: Dict = {}
        if since is not None:
            params["since"] = since
        if min_severity:
            params["severity"] = min_severity
        try:
            r = requests.get(
                f"{self.base_url}/events",
                params=params,
                timeout=self.timeout,
            )
            return r.json().get("events", []) if r.ok else []
        except Exception:
            return []

    def clear_events(self) -> bool:
        """
        Clear the agent's event buffer.

        Returns:
            True if the buffer was cleared successfully.
        """
        try:
            r = requests.delete(f"{self.base_url}/events", timeout=self.timeout)
            return r.ok
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def print_status(self) -> None:
        """Print a Rich-formatted health summary to the console."""
        h = self.health()
        if h is None:
            console.print(
                f"[red]sentinel-agent unreachable at {self.base_url}[/red]"
            )
            return
        mode_color = "green" if h.get("mode") == "ebpf" else "yellow"
        console.print(
            f"[bold]sentinel-agent[/bold] "
            f"[{mode_color}]{h.get('mode', 'unknown')}[/{mode_color}] | "
            f"kernel={h.get('kernel', '?')} | "
            f"events={h.get('events_captured', 0)} | "
            f"monitoring={'[green]active[/green]' if h.get('monitoring_active') else '[dim]idle[/dim]'}"
        )
