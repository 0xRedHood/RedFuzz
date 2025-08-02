#!/usr/bin/env python3
"""
RedFuzz TUI (Text User Interface)
A beautiful terminal interface for RedFuzz using Rich library
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
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.progress = None
        self.live = None
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'current_url': '',
            'current_payload': '',
            'start_time': None,
            'status': 'Initializing...',
            'vulnerabilities': []
        }
        self.lock = threading.Lock()
        
    def setup_layout(self):
        """Setup the main layout structure"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="stats", ratio=1)
        )
        
    def create_header(self):
        """Create the header panel"""
        title = Text("🔴 RedFuzz v5.0.0 - Advanced Web Security Fuzzer", style="bold red")
        subtitle = Text("Real-time vulnerability scanning with enhanced detection", style="dim")
        
        header_content = Align.center(
            title + "\n" + subtitle,
            vertical="middle"
        )
        
        return Panel(
            header_content,
            style="red",
            box=box.DOUBLE
        )
    
    def create_progress_section(self):
        """Create the main progress section"""
        progress_table = Table.grid()
        progress_table.add_column("Progress", ratio=1)
        
        # Main progress bar - only create once
        if not hasattr(self, 'progress') or self.progress is None:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                expand=True
            )
            
            # Add tasks
            self.scan_task = self.progress.add_task("Scanning URLs", total=100)
            self.payload_task = self.progress.add_task("Testing Payloads", total=100)
            self.crawl_task = self.progress.add_task("Crawling Website", total=100)
        
        progress_table.add_row(self.progress)
        
        # Current activity
        current_activity = Table.grid()
        current_activity.add_column("Activity", ratio=1)
        
        with self.lock:
            url_text = Text(f"URL: {self.stats['current_url']}", style="cyan")
            payload_text = Text(f"Payload: {self.stats['current_payload']}", style="yellow")
            status_text = Text(f"Status: {self.stats['status']}", style="green")
        
        current_activity.add_row(url_text)
        current_activity.add_row(payload_text)
        current_activity.add_row(status_text)
        
        return Panel(
            progress_table,
            title="[bold blue]Progress",
            border_style="blue"
        )
    
    def create_stats_section(self):
        """Create the statistics section"""
        stats_table = Table(title="[bold green]Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="yellow")
        
        with self.lock:
            stats_table.add_row("Total Requests", str(self.stats['total_requests']))
            stats_table.add_row("Vulnerabilities", str(self.stats['vulnerabilities_found']))
            
            if self.stats['start_time']:
                elapsed = time.time() - self.stats['start_time']
                stats_table.add_row("Elapsed Time", f"{elapsed:.1f}s")
            
            # Recent vulnerabilities
            if self.stats['vulnerabilities']:
                recent_vulns = self.stats['vulnerabilities'][-3:]  # Last 3
                vuln_text = "\n".join([f"• {v['type']} on {v['url']}" for v in recent_vulns])
                stats_table.add_row("Recent Finds", vuln_text)
        
        return Panel(
            stats_table,
            title="[bold green]Live Stats",
            border_style="green"
        )
    
    def create_footer(self):
        """Create the footer with controls"""
        footer_text = Text(
            "Press Ctrl+C to stop | RedFuzz v5.0.0 by 0xRedHood",
            style="dim"
        )
        
        return Panel(
            Align.center(footer_text),
            style="dim",
            box=box.SIMPLE
        )
    
    def update_stats(self, **kwargs):
        """Update statistics thread-safely"""
        with self.lock:
            self.stats.update(kwargs)
            
            # Update progress bars based on stats
            if 'total_requests' in kwargs:
                total_requests = kwargs['total_requests']
                # Update payload testing progress
                if hasattr(self, 'payload_task') and self.progress:
                    total_expected = self.stats.get('total_expected_requests', 100)
                    if total_expected > 0:
                        progress_percent = min((total_requests / total_expected) * 100, 100)
                        self.progress.update(self.payload_task, completed=int(progress_percent), total=100)
            
            # Update URL scanning progress based on current activity
            if 'current_url' in kwargs and hasattr(self, 'scan_task') and self.progress:
                # Get current progress and increment it
                current_progress = self.progress.tasks[self.scan_task].completed
                total_urls = self.stats.get('total_urls', 100)
                
                if total_urls > 0:
                    # Calculate progress based on URLs scanned
                    if 'urls_scanned' in self.stats:
                        urls_scanned = self.stats['urls_scanned']
                        scan_progress = min((urls_scanned / total_urls) * 100, 100)
                        self.progress.update(self.scan_task, completed=int(scan_progress), total=100)
                    else:
                        # Increment progress gradually
                        new_progress = min(current_progress + 2, 95)  # Don't go to 100% until done
                        self.progress.update(self.scan_task, completed=int(new_progress), total=100)
    
    def add_vulnerability(self, vuln_type, url, payload, evidence):
        """Add a new vulnerability to the list"""
        with self.lock:
            self.stats['vulnerabilities'].append({
                'type': vuln_type,
                'url': url,
                'payload': payload,
                'evidence': evidence,
                'time': datetime.now().strftime("%H:%M:%S")
            })
            self.stats['vulnerabilities_found'] += 1
    
    def set_total_requests(self, total):
        """Set the total number of expected requests for progress calculation"""
        with self.lock:
            self.stats['total_expected_requests'] = total
            if hasattr(self, 'payload_task') and self.progress:
                self.progress.update(self.payload_task, total=total)
    
    def set_total_urls(self, total):
        """Set the total number of URLs to scan"""
        with self.lock:
            self.stats['total_urls'] = total
            if hasattr(self, 'scan_task') and self.progress:
                self.progress.update(self.scan_task, total=total)
    
    def update_url_progress(self, urls_scanned):
        """Update URL scanning progress"""
        with self.lock:
            self.stats['urls_scanned'] = urls_scanned
            if hasattr(self, 'scan_task') and self.progress:
                total_urls = self.stats.get('total_urls', 100)
                if total_urls > 0:
                    progress_percent = (urls_scanned / total_urls) * 100
                    self.progress.update(self.scan_task, completed=int(progress_percent), total=100)
                else:
                    # If no total set, just show some progress
                    self.progress.update(self.scan_task, completed=urls_scanned, total=100)
    
    def update_crawl_progress(self, progress_percent):
        """Update crawling progress"""
        with self.lock:
            if hasattr(self, 'crawl_task') and self.progress:
                self.progress.update(self.crawl_task, completed=int(progress_percent), total=100)
    
    def set_crawl_total(self, total):
        """Set total crawl steps"""
        with self.lock:
            self.stats['crawl_total'] = total
            if hasattr(self, 'crawl_task') and self.progress:
                self.progress.update(self.crawl_task, total=total)
    
    def update_progress(self, task_name, completed, total):
        """Update progress bars"""
        if self.progress:
            if task_name == "Scanning URLs" and hasattr(self, 'scan_task'):
                self.progress.update(self.scan_task, completed=completed, total=total)
            elif task_name == "Testing Payloads" and hasattr(self, 'payload_task'):
                self.progress.update(self.payload_task, completed=completed, total=total)
    
    def complete_progress(self, task_name):
        """Mark a progress bar as completed (100%)"""
        if self.progress:
            if task_name == "Scanning URLs" and hasattr(self, 'scan_task'):
                self.progress.update(self.scan_task, completed=100, total=100)
            elif task_name == "Testing Payloads" and hasattr(self, 'payload_task'):
                self.progress.update(self.payload_task, completed=100, total=100)
            elif task_name == "Crawling Website" and hasattr(self, 'crawl_task'):
                self.progress.update(self.crawl_task, completed=100, total=100)
    
    def start(self):
        """Start the TUI"""
        self.setup_layout()
        self.stats['start_time'] = time.time()
        
        self.live = Live(
            self.layout,
            refresh_per_second=4,
            screen=True
        )
        
        self.running = True
        
        with self.live:
            while self.running:
                try:
                    # Update layout components
                    self.layout["header"].update(self.create_header())
                    self.layout["progress"].update(self.create_progress_section())
                    self.layout["stats"].update(self.create_stats_section())
                    self.layout["footer"].update(self.create_footer())
                    
                    time.sleep(0.25)
                    
                except KeyboardInterrupt:
                    self.running = False
                    break
    
    def stop(self):
        """Stop the TUI"""
        self.running = False
        if hasattr(self, 'live') and self.live:
            self.live.stop()
            # Clear the screen after stopping
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_summary(self, results):
        """Show final summary"""
        self.console.clear()
        
        # Create summary table
        summary_table = Table(title="[bold red]RedFuzz Scan Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")
        
        summary_table.add_row("Total URLs Scanned", str(len(results) if results else 0))
        summary_table.add_row("Vulnerabilities Found", str(self.stats['vulnerabilities_found']))
        summary_table.add_row("Total Requests", str(self.stats['total_requests']))
        
        if self.stats['start_time']:
            elapsed = time.time() - self.stats['start_time']
            summary_table.add_row("Total Time", f"{elapsed:.1f} seconds")
        
        # Show vulnerabilities
        if self.stats['vulnerabilities']:
            vuln_table = Table(title="[bold red]Vulnerabilities Found")
            vuln_table.add_column("Time", style="cyan")
            vuln_table.add_column("Type", style="red")
            vuln_table.add_column("URL", style="yellow")
            vuln_table.add_column("Payload", style="green")
            
            for vuln in self.stats['vulnerabilities']:
                vuln_table.add_row(
                    vuln['time'],
                    vuln['type'],
                    vuln['url'][:50] + "..." if len(vuln['url']) > 50 else vuln['url'],
                    vuln['payload'][:30] + "..." if len(vuln['payload']) > 30 else vuln['payload']
                )
            
            self.console.print(summary_table)
            self.console.print("\n")
            self.console.print(vuln_table)
        else:
            self.console.print(summary_table)
            self.console.print("\n[green]No vulnerabilities found![/green]")

# Global TUI instance
tui_instance = None

def init_tui():
    """Initialize the TUI"""
    global tui_instance
    tui_instance = RedFuzzTUI()
    return tui_instance

def get_tui():
    """Get the global TUI instance"""
    return tui_instance

if __name__ == "__main__":
    # Test the TUI
    tui = RedFuzzTUI()
    
    # Simulate some activity
    def simulate_activity():
        for i in range(10):
            tui.update_stats(
                total_requests=i*10,
                current_url=f"http://example.com/page{i}.php",
                current_payload=f"payload_{i}",
                status="Testing..."
            )
            if i % 3 == 0:
                tui.add_vulnerability(
                    "SQL Injection",
                    f"http://example.com/page{i}.php",
                    f"'; DROP TABLE users; --",
                    "Database error detected"
                )
            time.sleep(1)
    
    # Start simulation in background
    import threading
    sim_thread = threading.Thread(target=simulate_activity)
    sim_thread.daemon = True
    sim_thread.start()
    
    # Start TUI
    tui.start() 