import os
import sys
import subprocess
import threading
import time
from optparse import OptionParser
from concurrent.futures import ThreadPoolExecutor

# ANSI Color codes for better output
class Colors:
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_status(msg):
    print(f"{Colors.CYAN}[+]{Colors.ENDC} {msg}")

def print_success(msg):
    print(f"{Colors.GREEN}[*]{Colors.ENDC} {Colors.BOLD}{msg}{Colors.ENDC}")

def print_error(msg):
    print(f"{Colors.RED}[-]{Colors.ENDC} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.ENDC} {msg}")

def print_info(msg):
    print(f"{Colors.BLUE}[i]{Colors.ENDC} {msg}")

def print_task(msg):
    print(f"{Colors.MAGENTA}[>]{Colors.ENDC} {Colors.UNDERLINE}{msg}{Colors.ENDC}")

class blitz:
    def __init__(self, domain, screenshot=False, screenshot_tool="gowitness"):
        self.domain = domain
        self.screenshot = screenshot
        self.screenshot_tool = screenshot_tool
        self.base_dir = domain
        self.recon_dir = os.path.join(self.base_dir, "recon")
        self.threads = 50  # Increased default concurrency
        # Core tools from original script
        self.required_tools = ["assetfinder", "httprobe", "subjack", "nmap", "waybackurls"]
        # Optional high-speed tools for "more added features"
        self.extra_tools = ["subfinder", "httpx"]
        if screenshot:
            self.required_tools.append(screenshot_tool)

    def check_dependencies(self):
        print_info("Verifying all required tool dependencies...")
        missing_required = []
        for tool in self.required_tools:
            if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                missing_required.append(tool)
        
        if missing_required:
            print_error(f"Missing REQUIRED tools: {', '.join(missing_required)}")
            sys.exit(1)
            
        self.available_extras = []
        for tool in self.extra_tools:
            if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                self.available_extras.append(tool)
        
        print_success("Dependencies verified.")

    def setup_dirs(self):
        print_info("Setting up output directory structure...")
        dirs = [
            self.recon_dir,
            os.path.join(self.recon_dir, "scans"),
            os.path.join(self.recon_dir, "httprobe"),
            os.path.join(self.recon_dir, "potential_takeovers"),
            os.path.join(self.recon_dir, "wayback"),
            os.path.join(self.recon_dir, "wayback/params"),
            os.path.join(self.recon_dir, "wayback/extensions"),
            os.path.join(self.recon_dir, "screenshots")
        ]
        for d in dirs:
            if not os.path.exists(d):
                os.makedirs(d)

    def run_command(self, cmd, output_file=None, append=False):
        try:
            if output_file:
                mode = "a" if append else "w"
                with open(output_file, mode) as f:
                    subprocess.run(cmd, shell=True, check=True, stdout=f, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def harvest_subdomains(self):
        print_status("Harvesting subdomains (Parallel Discovery)...")
        final_txt = os.path.join(self.recon_dir, "final.txt")
        temp_assets = os.path.join(self.recon_dir, "assets_tmp.txt")
        
        cmds = [f"assetfinder --subs-only {self.domain} >> {temp_assets}"]
        if "subfinder" in self.available_extras:
            # Use 100 threads for subfinder
            cmds.append(f"subfinder -d {self.domain} -t 100 -silent >> {temp_assets}")
            
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.map(lambda cmd: self.run_command(cmd), cmds)
            
        if os.path.exists(temp_assets):
            cmd_clean = f"grep {self.domain} {temp_assets} | sort -u > {final_txt} && rm {temp_assets}"
            self.run_command(cmd_clean)
        
        if os.path.exists(final_txt):
            with open(final_txt, 'r') as f:
                print_success(f"Found {len(f.readlines())} unique subdomains.")

    def probe_alive(self):
        print_status("Probing for alive domains (High-speed Probing)...")
        final_txt = os.path.join(self.recon_dir, "final.txt")
        alive_txt = os.path.join(self.recon_dir, "httprobe/alive.txt")
        temp_alive = os.path.join(self.recon_dir, "httprobe/alive_tmp.txt")
        
        if not os.path.exists(final_txt) or os.path.getsize(final_txt) == 0:
            return

        cmds = []
        if "httpx" in self.available_extras:
            # httpx is significantly faster, use it as primary with 100 threads
            cmds.append(rf"httpx -l {final_txt} -t 100 -silent | sed 's/https\?:\/\/\\?//' >> {temp_alive}")
            cmds.append(f"httpx -l {final_txt} -t 100 -silent -sc -td -title > {os.path.join(self.recon_dir, 'httprobe/httpx_detailed.txt')}")
        else:
            cmds.append(rf"cat {final_txt} | httprobe -s -p https:443 | sed 's/https\?:\/\/\\?//' | tr -d ':443' >> {temp_alive}")

        with ThreadPoolExecutor(max_workers=len(cmds)) as executor:
            executor.map(lambda cmd: self.run_command(cmd), cmds)
            
        if os.path.exists(temp_alive):
            self.run_command(f"sort -u {temp_alive} > {alive_txt} && rm {temp_alive}")
        
        if os.path.exists(alive_txt):
            with open(alive_txt, 'r') as f:
                print_success(f"Found {len(f.readlines())} alive domains.")

    def check_takeovers(self):
        print_status("Checking for takeovers (Parallel)...")
        final_txt = os.path.join(self.recon_dir, "final.txt")
        output = os.path.join(self.recon_dir, "potential_takeovers/potential_takeovers.txt")
        fingerprints = os.path.expanduser("~/go/src/github.com/haccer/subjack/fingerprints.json")
        
        # Increase subjack threads to 200
        fp_arg = f"-c {fingerprints}" if os.path.exists(fingerprints) else ""
        cmd = f"subjack -w {final_txt} -t 200 -timeout 30 -ssl {fp_arg} -v 3 -o {output}"
        self.run_command(cmd)

    def scan_ports(self):
        print_status("Scanning for open ports (Fast Nmap)...")
        alive_txt = os.path.join(self.recon_dir, "httprobe/alive.txt")
        output_prefix = os.path.join(self.recon_dir, "scans/scanned")
        if os.path.getsize(alive_txt) > 0:
            # Use -T5 and --min-rate for aggressive speed
            cmd = f"nmap -iL {alive_txt} -T5 --min-rate 1000 -F -oA {output_prefix}"
            self.run_command(cmd)

    def wayback_data(self):
        print_status("Scraping wayback data (Fast Scraping)...")
        final_txt = os.path.join(self.recon_dir, "final.txt")
        wayback_output = os.path.join(self.recon_dir, "wayback/wayback_output.txt")
        cmd = f"cat {final_txt} | waybackurls | sort -u"
        self.run_command(cmd, wayback_output)

        print_info("Compiling params and extensions (Parallel)...")
        params_file = os.path.join(self.recon_dir, "wayback/params/wayback_params.txt")
        self.run_command(f"grep '?*=' {wayback_output} | cut -d '=' -f 1 | sort -u", params_file)

        extensions = ['js', 'php', 'aspx', 'jsp', 'json', 'html']
        def sort_ext(ext):
            ext_file = os.path.join(self.recon_dir, f"wayback/extensions/{ext}.txt")
            self.run_command(f"grep -E '\\.{ext}(\\?|$)' {wayback_output} | sort -u", ext_file)

        with ThreadPoolExecutor(max_workers=len(extensions)) as executor:
            executor.map(sort_ext, extensions)

    def take_screenshots(self):
        if not self.screenshot: return
        print_status(f"Taking screenshots with {self.screenshot_tool} (Concurrent)...")
        alive_txt = os.path.join(self.recon_dir, "httprobe/alive.txt")
        output_dir = os.path.join(self.recon_dir, "screenshots")
        
        if self.screenshot_tool == "gowitness":
            cmd = f"gowitness file -f {alive_txt} --threads 20 --destination {output_dir}"
        else: # EyeWitness
            cmd = f"python3 EyeWitness.py --web -f {alive_txt} -d {output_dir} --resolve --no-prompt --threads 20"
        
        self.run_command(cmd)

    def run(self):
        self.check_dependencies()
        self.setup_dirs()
        
        start_time = time.time()
        
        # Sequence matters for some, others can be parallelized
        self.harvest_subdomains()
        self.probe_alive()
        
        # These can run in parallel
        print_task("Starting parallelized recon engine (Takeovers, Ports, Wayback)...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            executor.submit(self.check_takeovers)
            executor.submit(self.scan_ports)
            executor.submit(self.wayback_data)
        
        if self.screenshot:
            self.take_screenshots()
            
        end_time = time.time()
        print_success(f"⚡ blitz recon completed in {round(end_time - start_time, 2)} seconds. ⚡")

def main():
    usage = "usage: %prog [options] domain"
    description = """
blitz: High-Speed Multi-threaded Recon Tool
--------------------------------------------
This tool automates subdomain discovery, alive probing, port scanning,
wayback data scraping, and optional screenshotting. It is designed to
be significantly faster than the original bash script by using 
multi-threading and high-performance tools like httpx and subfinder.
    """
    
    parser = OptionParser(usage=usage, description=description)
    
    parser.add_option("-s", "--screenshot", action="store_true", dest="screenshot", default=False,
                      help="Enable automated screenshotting of alive domains.")
    
    parser.add_option("-t", "--tool", dest="tool", default="gowitness",
                      help="Specify the screenshot tool to use (gowitness or eyewitness). [default: %default]")

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                      help="Enable verbose output for debugging.")

    # Add examples to the help menu
    parser.epilog = """
Examples:
  python3 %prog example.com                  # Basic fast recon
  python3 %prog example.com -s               # Recon + screenshots (gowitness)
  python3 %prog example.com -s -t eyewitness # Recon + screenshots (eyewitness)
    """
    
    (options, args) = parser.parse_args()
    
    if len(args) != 1:
        print_error("Error: Domain is a required argument.")
        print("Use -h or --help for detailed instructions.")
        sys.exit(1)
    
    domain = args[0]
    recon = blitz(domain, screenshot=options.screenshot, screenshot_tool=options.tool)
    
    try:
        recon.run()
    except KeyboardInterrupt:
        print_error("\nInterrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print_error(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
