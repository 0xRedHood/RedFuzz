#!/usr/bin/env python3
"""
RedFuzz TUI (Text User Interface) - REFINED
A beautiful and reliable terminal interface for RedFuzz using the Rich library.
"""

import time
import threading
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich import box

class RedFuzzTUI:
    """Manages the Text User Interface for RedFuzz"""

    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.progress = None
        self.live = None
        self.running = False

        # Thread-safe statistics dictionary
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'current_url': 'N/A',
            'current_payload': 'N/A',
            'start_time': None,
            'status': 'Initializing...',
            'vulnerabilities': [],
            'total_expected_requests': 0,
            'total_urls': 0
        }
        self.lock = threading.Lock()
        
    def setup_layout(self):
        """Setup the main layout structure - IMPROVED LAYOUT"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        self.layout["left"].split_column(
            Layout(name="progress", size=7),
            Layout(name="vulnerabilities", ratio=1)
        )

    def create_header(self) -> Panel:
        """Create the header panel with title and subtitle"""
        title = Text("🔴 RedFuzz v5.0.0 - Advanced Web Security Fuzzer", style="bold red")
        subtitle = Text("Real-time vulnerability scanning with enhanced detection", style="dim")
        
        header_content = Align.center(f"{title}\n{subtitle}", vertical="middle")
        
        return Panel(header_content, style="red", box=box.DOUBLE)
    
    def create_progress_section(self) -> Panel:
        """Create the main progress section with multiple progress bars"""
        progress_table = Table.grid(expand=True)
        
        # Initialize progress bars only once
        if self.progress is None:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                expand=True
            )
            
            # Add tasks for different stages of the scan
            self.crawl_task = self.progress.add_task("Crawling Website", total=100, visible=False)
            self.scan_task = self.progress.add_task("Scanning URLs", total=100)
            self.payload_task = self.progress.add_task("Testing Payloads", total=100)
        
        progress_table.add_row(self.progress)
        
        # Display current activity details
        with self.lock:
            url = self.stats['current_url']
            payload = self.stats['current_payload']
            status = self.stats['status']
        
        activity_text = Text.assemble(
            ("URL: ", "bold cyan"), (f"{url[:60]}...\n", "white"),
            ("Payload: ", "bold yellow"), (f"{payload[:60]}...\n", "white"),
            ("Status: ", "bold green"), (f"{status}", "white")
        )

        progress_table.add_row(activity_text)

        return Panel(progress_table, title="[bold blue]Scan Progress", border_style="blue")
    
    def create_stats_section(self) -> Panel:
        """Create the statistics section with live counters"""
        with self.lock:
            total_req = self.stats['total_requests']
            vuln_found = self.stats['vulnerabilities_found']
            start_time = self.stats['start_time']

        stats_table = Table(title="[bold green]Live Statistics")
        stats_table.add_column("Metric", style="cyan", justify="right")
        stats_table.add_column("Value", style="yellow", justify="left")
        
        stats_table.add_row("Total Requests", f"{total_req:,}")
        stats_table.add_row("Vulnerabilities", str(vuln_found))

        if start_time:
            elapsed = time.time() - start_time
            stats_table.add_row("Elapsed Time", f"{elapsed:.1f}s")

        return Panel(stats_table, title="[bold green]Live Stats", border_style="green")

    def create_vulnerabilities_section(self) -> Panel:
        """Create a section to display recently discovered vulnerabilities"""
        with self.lock:
            recent_vulns = self.stats['vulnerabilities'][-5:]  # Display last 5 vulnerabilities
        
        vuln_table = Table(title="[bold red]Recent Vulnerabilities")
        vuln_table.add_column("Time", style="dim")
        vuln_table.add_column("Type", style="red")
        vuln_table.add_column("URL", style="yellow")

        for vuln in recent_vulns:
            vuln_table.add_row(
                vuln['time'],
                vuln['type'],
                f"{vuln['url'][:30]}..." if len(vuln['url']) > 30 else vuln['url']
            )

        return Panel(vuln_table, title="[bold red]Vulnerability Feed", border_style="red")
    
    def create_footer(self) -> Panel:
        """Create the footer with controls and credits"""
        footer_text = Text(
            "Press Ctrl+C to stop | RedFuzz v5.0.0 by 0xRedHood",
            style="dim"
        )
        return Panel(Align.center(footer_text), style="dim", box=box.SIMPLE)
    
    def update_stats(self, **kwargs):
        """Update statistics thread-safely - NO MORE PROGRESS UPDATES HERE"""
        with self.lock:
            self.stats.update(kwargs)
    
    def add_vulnerability(self, vuln_type: str, url: str, payload: str, evidence: str):
        """Add a new vulnerability to the list (thread-safe)"""
        with self.lock:
            self.stats['vulnerabilities'].append({
                'type': vuln_type,
                'url': url,
                'payload': payload,
                'evidence': evidence,
                'time': datetime.now().strftime("%H:%M:%S")
            })
            self.stats['vulnerabilities_found'] += 1
    
    def set_total_requests(self, total: int):
        """Set the total number of expected requests for progress calculation"""
        with self.lock:
            self.stats['total_expected_requests'] = total
            if self.progress:
                self.progress.update(self.payload_task, total=total, completed=0)
    
    def set_total_urls(self, total: int):
        """Set the total number of URLs to scan"""
        with self.lock:
            self.stats['total_urls'] = total
            if self.progress:
                self.progress.update(self.scan_task, total=total, completed=0)

    def update_payload_progress(self, completed: int):
        """Update the payload testing progress bar"""
        with self.lock:
            if self.progress:
                self.progress.update(self.payload_task, completed=completed)

    def update_url_progress(self, completed: int):
        """Update URL scanning progress bar"""
        with self.lock:
            if self.progress:
                self.progress.update(self.scan_task, completed=completed)
    
    def update_crawl_progress(self, completed: int, visible: bool = True):
        """Update crawling progress and visibility"""
        with self.lock:
            if self.progress:
                self.progress.update(self.crawl_task, completed=completed, visible=visible)
    
    def start(self):
        """Start the TUI event loop"""
        self.setup_layout()
        self.stats['start_time'] = time.time()
        
        self.live = Live(self.layout, refresh_per_second=4, screen=True)
        self.running = True
        
        with self.live:
            while self.running:
                try:
                    # Update layout components with new data
                    self.layout["header"].update(self.create_header())
                    self.layout["progress"].update(self.create_progress_section())
                    self.layout["right"].update(
                        Layout(
                            self.create_stats_section(),
                            name="stats"
                        )
                    )
                    self.layout["vulnerabilities"].update(self.create_vulnerabilities_section())
                    self.layout["footer"].update(self.create_footer())
                    
                    time.sleep(0.25)
                except KeyboardInterrupt:
                    self.running = False
                    break
    
    def stop(self):
        """Stop the TUI and clear the screen"""
        self.running = False
        if self.live:
            self.live.stop()
            # Clear the screen after stopping for a clean exit
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_summary(self, results):
        """Show a final summary table after the scan is complete"""
        self.console.clear()
        
        # Create summary table
        summary_table = Table(title="[bold red]RedFuzz Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")
        
        summary_table.add_row("Total URLs Scanned", str(self.stats.get('total_urls', 0)))
        summary_table.add_row("Vulnerabilities Found", str(self.stats['vulnerabilities_found']))
        summary_table.add_row("Total Requests", str(self.stats['total_requests']))
        
        if self.stats['start_time']:
            elapsed = time.time() - self.stats['start_time']
            summary_table.add_row("Total Time", f"{elapsed:.1f} seconds")
        
        self.console.print(summary_table)

        # Show detailed vulnerabilities table
        if self.stats['vulnerabilities']:
            vuln_table = Table(title="[bold red]Discovered Vulnerabilities")
            vuln_table.add_column("Time", style="cyan")
            vuln_table.add_column("Type", style="red")
            vuln_table.add_column("URL", style="yellow")
            vuln_table.add_column("Payload", style="green")
            
            for vuln in self.stats['vulnerabilities']:
                vuln_table.add_row(
                    vuln['time'],
                    vuln['type'],
                    (vuln['url'][:50] + "...") if len(vuln['url']) > 50 else vuln['url'],
                    (vuln['payload'][:30] + "...") if len(vuln['payload']) > 30 else vuln['payload']
                )
            
            self.console.print("\n")
            self.console.print(vuln_table)
        else:
            self.console.print("\n[bold green]✅ No vulnerabilities found![/bold green]")

# It's generally better to manage the TUI instance within the main application
# instead of using global variables. These functions are kept for potential
# backward compatibility but their use is discouraged.
tui_instance = None

def init_tui() -> RedFuzzTUI:
    """Initialize a global TUI instance"""
    global tui_instance
    if tui_instance is None:
        tui_instance = RedFuzzTUI()
    return tui_instance

def get_tui() -> RedFuzzTUI:
    """Get the global TUI instance"""
    return tui_instance

if __name__ == "__main__":
    # Example of how to use the new TUI
    tui = RedFuzzTUI()
    
    def simulate_scan():
        """Simulate a fuzzing scan to demonstrate TUI functionality"""
        tui.update_stats(status="Starting crawl...")
        tui.update_crawl_progress(0, visible=True)
        for i in range(101):
            tui.update_crawl_progress(i, visible=True)
            time.sleep(0.02)
        tui.update_crawl_progress(100, visible=False)

        total_urls = 50
        tui.set_total_urls(total_urls)
        tui.update_stats(status=f"Scanning {total_urls} URLs...")

        for i in range(total_urls + 1):
            tui.update_url_progress(i)
            tui.update_stats(current_url=f"http://example.com/page{i}.php")
            time.sleep(0.05)

            if i % 10 == 0:
                tui.add_vulnerability(
                    "SQL Injection",
                    f"http://example.com/page{i}.php?id=1",
                    "' OR 1=1--",
                    "Detected based on response difference."
                )

        total_payloads = 1000
        tui.set_total_requests(total_payloads)
        tui.update_stats(status=f"Testing {total_payloads} payloads...")

        for i in range(total_payloads + 1):
            tui.update_payload_progress(i)
            tui.update_stats(
                total_requests=i,
                current_payload=f"payload_{i}"
            )
            time.sleep(0.01)

            if i % 100 == 0:
                tui.add_vulnerability(
                    "XSS",
                    "http://example.com/search.php",
                    "<script>alert(1)</script>",
                    "Reflected in response."
                )

        tui.update_stats(status="Scan complete.")
        time.sleep(2)
        tui.stop()
        tui.show_summary([]) # In a real scenario, you'd pass the results here

    # Run the simulation in a background thread
    sim_thread = threading.Thread(target=simulate_scan, daemon=True)
    sim_thread.start()
    
    # Start the TUI
    tui.start()