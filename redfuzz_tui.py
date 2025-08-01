#!/usr/bin/env python3
"""
RedFuzz TUI - Text User Interface for RedFuzz
Author: RedFuzz Team
Version: 5.0.0
"""

import sys
import time
import threading
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from datetime import datetime
import json

class RedFuzzTUI:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.progress = None
        self.vulnerabilities = []
        self.stats = {
            'total_requests': 0,
            'vulnerabilities_found': 0,
            'current_url': '',
            'current_payload': '',
            'start_time': None,
            'elapsed_time': 0
        }
        self.running = False
        
    def setup_layout(self):
        """Setup the TUI layout"""
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        self.layout["main"].split_row(
            Layout(name="progress", ratio=2),
            Layout(name="vulns", ratio=1)
        )
        
    def create_header(self):
        """Create header panel"""
        header_text = Text("🔴 RedFuzz v4.0.0 - Advanced Web Application Fuzzer", style="bold red")
        header_text.append(" | ", style="white")
        header_text.append(f"Started: {datetime.now().strftime('%H:%M:%S')}", style="cyan")
        
        return Panel(header_text, box=box.ROUNDED, style="bold blue")
    
    def create_progress_section(self):
        """Create progress section"""
        if not self.progress:
            return Panel("Initializing...", title="Progress", box=box.ROUNDED)
        
        progress_text = f"""
Total Requests: {self.stats['total_requests']}
Vulnerabilities Found: {self.stats['vulnerabilities_found']}
Current URL: {self.stats['current_url']}
Current Payload: {self.stats['current_payload']}
Elapsed Time: {self.stats['elapsed_time']:.1f}s
        """
        
        return Panel(progress_text, title="Progress", box=box.ROUNDED)
    
    def create_vulnerabilities_section(self):
        """Create vulnerabilities section"""
        if not self.vulnerabilities:
            return Panel("No vulnerabilities found yet...", title="Vulnerabilities", box=box.ROUNDED)
        
        table = Table(title="Found Vulnerabilities", box=box.ROUNDED)
        table.add_column("Type", style="cyan")
        table.add_column("Parameter", style="magenta")
        table.add_column("Method", style="green")
        table.add_column("Status", style="yellow")
        
        for vuln in self.vulnerabilities[-5:]:  # Show last 5
            table.add_row(
                vuln.get('vulnerability_type', 'Unknown'),
                vuln.get('parameter', 'Unknown'),
                vuln.get('method', 'Unknown'),
                str(vuln.get('status_code', 'Unknown'))
            )
        
        return Panel(table, title="Vulnerabilities", box=box.ROUNDED)
    
    def create_footer(self):
        """Create footer panel"""
        footer_text = Text("Press Ctrl+C to stop | ", style="white")
        footer_text.append("RedFuzz v4.0.0", style="bold red")
        
        return Panel(footer_text, box=box.ROUNDED, style="dim")
    
    def update_layout(self):
        """Update the layout with current data"""
        self.layout["header"].update(self.create_header())
        self.layout["progress"].update(self.create_progress_section())
        self.layout["vulns"].update(self.create_vulnerabilities_section())
        self.layout["footer"].update(self.create_footer())
    
    def start_progress(self, total_requests):
        """Start the progress tracking"""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        )
        self.progress.add_task("Fuzzing", total=total_requests)
        self.stats['start_time'] = time.time()
        self.running = True
    
    def update_progress(self, current_request, total_requests, current_url="", current_payload=""):
        """Update progress information"""
        self.stats['total_requests'] = current_request
        self.stats['current_url'] = current_url
        self.stats['current_payload'] = current_payload
        if self.stats['start_time']:
            self.stats['elapsed_time'] = time.time() - self.stats['start_time']
        
        if self.progress:
            self.progress.update(0, completed=current_request, total=total_requests)
    
    def add_vulnerability(self, vuln):
        """Add a new vulnerability"""
        self.vulnerabilities.append(vuln)
        self.stats['vulnerabilities_found'] = len(self.vulnerabilities)
    
    def display_results(self, results):
        """Display final results"""
        self.console.clear()
        
        # Create results table
        table = Table(title="🔴 RedFuzz v4.0.0 - Final Results", box=box.ROUNDED)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Parameter", style="magenta")
        table.add_column("Method", style="green")
        table.add_column("Payload", style="yellow")
        table.add_column("URL", style="blue")
        table.add_column("Status", style="red")
        table.add_column("Response Time", style="green")
        
        vulnerable_results = [r for r in results if r and r.get('vulnerable')]
        
        for vuln in vulnerable_results:
            table.add_row(
                vuln.get('vulnerability_type', 'Unknown'),
                vuln.get('parameter', 'Unknown'),
                vuln.get('method', 'Unknown'),
                vuln.get('payload', 'Unknown')[:30] + "..." if len(vuln.get('payload', '')) > 30 else vuln.get('payload', 'Unknown'),
                vuln.get('url', 'Unknown')[:40] + "..." if len(vuln.get('url', '')) > 40 else vuln.get('url', 'Unknown'),
                str(vuln.get('status_code', 'Unknown')),
                f"{vuln.get('response_time', 0):.3f}s"
            )
        
        # Display summary
        summary = f"""
📊 Summary:
   • Total Requests: {len(results)}
   • Vulnerabilities Found: {len(vulnerable_results)}
   • Elapsed Time: {self.stats['elapsed_time']:.1f}s
   • Average Response Time: {sum(r.get('response_time', 0) for r in results) / len(results) if results else 0:.3f}s
        """
        
        self.console.print(Panel(summary, title="Summary", box=box.ROUNDED, style="bold green"))
        self.console.print(table)
        
        if vulnerable_results:
            self.console.print(Panel("🎯 Vulnerabilities Found!", style="bold red"))
        else:
            self.console.print(Panel("✅ No vulnerabilities detected", style="bold green"))
    
    def run_tui(self, fuzzer_instance):
        """Run the TUI with a fuzzer instance"""
        self.setup_layout()
        
        with Live(self.layout, refresh_per_second=4, screen=True):
            try:
                while self.running:
                    self.update_layout()
                    time.sleep(0.25)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Stopping RedFuzz...[/yellow]")
                self.running = False

def main():
    """Main function for TUI demo"""
    tui = RedFuzzTUI()
    
    # Demo data
    tui.start_progress(100)
    
    # Simulate progress
    for i in range(100):
        tui.update_progress(
            i + 1, 
            100, 
            f"https://example.com/page{i}", 
            f"payload_{i}"
        )
        
        if i % 10 == 0:
            tui.add_vulnerability({
                'vulnerability_type': 'SQL Injection',
                'parameter': 'id',
                'method': 'GET',
                'status_code': 200,
                'response_time': 0.123
            })
        
        time.sleep(0.1)
    
    # Display results
    demo_results = [
        {
            'vulnerable': True,
            'vulnerability_type': 'SQL Injection',
            'parameter': 'user',
            'method': 'POST',
            'payload': "' OR '1'='1",
            'url': 'https://example.com/login',
            'status_code': 200,
            'response_time': 0.245
        },
        {
            'vulnerable': True,
            'vulnerability_type': 'XSS',
            'parameter': 'Header: User-Agent',
            'method': 'HEADER',
            'payload': '<script>alert("XSS")</script>',
            'url': 'https://example.com',
            'status_code': 200,
            'response_time': 0.156
        }
    ]
    
    tui.display_results(demo_results)

if __name__ == "__main__":
    main() 