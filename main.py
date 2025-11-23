import argparse
from modules.port_scanner import scan_ports
from modules import service_detect, os_detect, vuln_checks
from utils import logger, report_gen

def main():
    parser = argparse.ArgumentParser(description="Mini-Nessus Scanner")
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("--ports", help="Comma separated ports, e.g. 80,443,22", default="80,443,22,21,23")
    parser.add_argument("--report", help="Save report as HTML", action="store_true")
    args = parser.parse_args()

    logger.info(f"Starting scan on target: {args.target}")
    ports = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]

    # Port scanning
    open_ports = scan_ports(args.target, ports)
    logger.good(f"Open ports found: {open_ports}")

    # Service detection
    services = []
    for port in open_ports:
        banner = service_detect.service_version(args.target, port)
        services.append(banner)
        logger.info(f"Port {port} banner: {banner}")

    # OS detection
    os_info = os_detect.detect_os(args.target)
    logger.warn(f"OS detection result: {os_info}")

    # Vulnerability checks
    vulns = []
    url = f"http://{args.target}"
    vulns += vuln_checks.check_missing_headers(url)
    vulns += vuln_checks.check_open_directory(url)
    vulns += vuln_checks.check_outdated_server('\n'.join(services))
    vulns += vuln_checks.check_robots_txt(url)
    # vulns += vuln_checks.check_default_creds(url)  # Placeholder for default creds

    if vulns:
        logger.info("Vulnerabilities found:")
        for v in vulns:
            logger.fail(v)
    else:
        logger.good("No vulnerabilities found!")

    # Reporting
    if args.report:
        results = {
            'target': args.target,
            'open_ports': open_ports,
            'services': services,
            'os': os_info,
            'vulns': vulns
        }
        html_report = report_gen.generate_html_report(results)
        logger.good(f"HTML report saved to: {html_report}")

if __name__ == "__main__":
    main()
