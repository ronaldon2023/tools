  """
  PII Scanner - Enterprise-grade PII detection and auditing tool

  Scans data sources (databases, files, APIs, text) for Personally Identifiable
  Information (PII) to ensure GDPR, CCPA, and SOC 2 compliance.

  Usage:
      # Scan a database table
      python pii_scanner.py --db postgres://user:pass@host/db --table users

      # Scan JSON files
      python pii_scanner.py --file data/*.json --output report.html

      # Scan text/logs
      echo "Email: john@example.com" | python pii_scanner.py --stdin

      # Generate compliance report
      python pii_scanner.py --db postgres://... --compliance-report soc2
  """

  import re
  import json
  import argparse
  import sys
  from typing import Dict, List, Set, Optional, Any, Tuple
  from dataclasses import dataclass, asdict
  from enum import Enum
  from datetime import datetime
  import hashlib


  class PIIType(Enum):
      """PII entity types"""
      CREDIT_CARD = "CREDIT_CARD"
      SSN = "SSN"
      IBAN = "IBAN"
      BITCOIN = "BITCOIN"
      AWS_KEY = "AWS_KEY"
      API_KEY = "API_KEY"
      IPV6 = "IPV6"
      IPV4 = "IPV4"
      PHONE = "PHONE"
      EMAIL = "EMAIL"


  class Severity(Enum):
      """PII severity levels for compliance"""
      CRITICAL = "CRITICAL"  # SSN, credit card, API keys
      HIGH = "HIGH"          # Email, phone, IBAN
      MEDIUM = "MEDIUM"      # IP addresses
      LOW = "LOW"            # Generic identifiers


  @dataclass
  class PIIMatch:
      """Represents a detected PII occurrence"""
      pii_type: PIIType
      severity: Severity
      matched_text: str      # Partial (redacted for logging)
      location: str          # Where found (table.column, file:line, etc.)
      context: str           # Surrounding text (redacted)
      timestamp: str

      def to_dict(self) -> Dict:
          return {
              'pii_type': self.pii_type.value,
              'severity': self.severity.value,
              'matched_text': self.matched_text,
              'location': self.location,
              'context': self.context,
              'timestamp': self.timestamp
          }


  @dataclass
  class ScanResult:
      """Complete scan results"""
      total_scanned: int
      pii_found: int
      matches: List[PIIMatch]
      summary: Dict[str, int]  # PII type -> count
      severity_summary: Dict[str, int]  # Severity -> count
      scan_duration_ms: float

      def to_dict(self) -> Dict:
          return {
              'total_scanned': self.total_scanned,
              'pii_found': self.pii_found,
              'matches': [m.to_dict() for m in self.matches],
              'summary': self.summary,
              'severity_summary': self.severity_summary,
              'scan_duration_ms': self.scan_duration_ms
          }


  class PIIScanner:
      """Core PII detection engine"""

      # PII patterns with severity mappings
      PATTERNS = [
          {
              'type': PIIType.CREDIT_CARD,
              'regex': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b'),
              'severity': Severity.CRITICAL,
              'validator': 'validate_credit_card'
          },
          {
              'type': PIIType.SSN,
              'regex': re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
              'severity': Severity.CRITICAL,
              'validator': 'validate_ssn'
          },
          {
              'type': PIIType.IBAN,
              'regex': re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'),
              'severity': Severity.HIGH,
              'validator': None
          },
          {
              'type': PIIType.BITCOIN,
              'regex': re.compile(r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b'),
              'severity': Severity.CRITICAL,
              'validator': None
          },
          {
              'type': PIIType.AWS_KEY,
              'regex': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
              'severity': Severity.CRITICAL,
              'validator': None
          },
          {
              'type': PIIType.API_KEY,
              'regex': re.compile(r'\b(sk-|pk-|ghp_|gho_|ghg_|rg-)[A-Za-z0-9_-]{20,}\b'),
              'severity': Severity.CRITICAL,
              'validator': None
          },
          {
              'type': PIIType.IPV6,
              'regex': re.compile(r'::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'),
              'severity': Severity.MEDIUM,
              'validator': 'validate_ipv6'
          },
          {
              'type': PIIType.IPV4,
              'regex': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
              'severity': Severity.MEDIUM,
              'validator': 'validate_ipv4'
          },
          {
              'type': PIIType.PHONE,
              'regex': re.compile(r'\+?\d{1,4}[\s\-.]?\(?\d{1,4}\)?[\s\-.]?\d{1,4}[\s\-.]?\d{1,4}[\s\-.]?\d{0,4}\b'),
              'severity': Severity.HIGH,
              'validator': 'validate_phone'
          },
          {
              'type': PIIType.EMAIL,
              'regex': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
              'severity': Severity.HIGH,
              'validator': None
          },
      ]

      def __init__(self, strict_mode: bool = True):
          self.strict_mode = strict_mode

      def scan_text(self, text: str, location: str = "unknown") -> List[PIIMatch]:
          """Scan text for PII occurrences"""
          if not isinstance(text, str):
              return []

          matches = []

          for pattern in self.PATTERNS:
              for match in pattern['regex'].finditer(text):
                  matched_text = match.group(0)

                  # Validate match if validator exists
                  if pattern['validator']:
                      validator = getattr(self, pattern['validator'])
                      if not validator(matched_text):
                          continue

                  # Extract context (20 chars before/after, redacted)
                  start = max(0, match.start() - 20)
                  end = min(len(text), match.end() + 20)
                  context = text[start:end]

                  # Redact the actual PII in context for safe logging
                  context_redacted = context.replace(matched_text, '[REDACTED]')

                  # Hash matched text for unique identification without exposing PII
                  matched_hash = hashlib.sha256(matched_text.encode()).hexdigest()[:8]

                  matches.append(PIIMatch(
                      pii_type=pattern['type'],
                      severity=pattern['severity'],
                      matched_text=f"[{pattern['type'].value}:{matched_hash}]",
                      location=location,
                      context=context_redacted,
                      timestamp=datetime.utcnow().isoformat()
                  ))

          return matches

      def scan_dict(self, data: Dict, location: str = "", prefix: str = "") -> List[PIIMatch]:
          """Recursively scan dictionary/JSON for PII"""
          matches = []

          # Support both 'location' and 'prefix' for backward compatibility
          base_location = location or prefix

          for key, value in data.items():
              current_location = f"{base_location}.{key}" if base_location else key

              if isinstance(value, str):
                  matches.extend(self.scan_text(value, current_location))
              elif isinstance(value, dict):
                  matches.extend(self.scan_dict(value, location=current_location))
              elif isinstance(value, list):
                  for i, item in enumerate(value):
                      if isinstance(item, str):
                          matches.extend(self.scan_text(item, f"{current_location}[{i}]"))
                      elif isinstance(item, dict):
                          matches.extend(self.scan_dict(item, location=f"{current_location}[{i}]"))

          return matches

      # Validators

      def validate_credit_card(self, card_num: str) -> bool:
          """Validate credit card using Luhn algorithm"""
          digits = [int(d) for d in card_num if d.isdigit()]

          if len(digits) not in [15, 16]:
              return False

          if self.strict_mode:
              return True  # Redact all 15-16 digit patterns in strict mode

          # Luhn validation
          checksum = 0
          for i, d in enumerate(reversed(digits)):
              if i % 2 == 1:
                  d *= 2
                  if d > 9:
                      d -= 9
              checksum += d

          return checksum % 10 == 0

      def validate_ssn(self, ssn: str) -> bool:
          """Validate SSN format"""
          digits = ''.join(c for c in ssn if c.isdigit())

          if len(digits) != 9:
              return False

          # Reject obvious invalids
          if len(set(digits)) == 1:  # All same digit
              return False
          if digits.startswith('000'):
              return False

          return True

      def validate_phone(self, phone: str) -> bool:
          """Validate phone number"""
          digits = ''.join(c for c in phone if c.isdigit())

          # Reject credit card/SSN lengths
          if len(digits) in [9, 15, 16]:
              return False

          return 7 <= len(digits) <= 14

      def validate_ipv4(self, ip: str) -> bool:
          """Validate IPv4 address"""
          parts = ip.split('.')
          try:
              return all(0 <= int(p) <= 255 for p in parts)
          except ValueError:
              return False

      def validate_ipv6(self, ip: str) -> bool:
          """Validate IPv6 address"""
          # Must contain at least 2 colons
          if ip.count(':') < 2:
              return False

          # Handle IPv4-mapped format
          if '.' in ip:
              if not ip.startswith('::'):
                  return False
              ipv4_part = ip.split(':')[-1]
              return self.validate_ipv4(ipv4_part)

          # Validate segments
          segments = ip.split(':')
          for seg in segments:
              if seg and (len(seg) > 4 or not all(c in '0123456789abcdefABCDEF' for c in seg)):
                  return False

          return 3 <= len(segments) <= 9


  class DatabaseScanner:
      """Scan database tables for PII"""

      def __init__(self, scanner: PIIScanner):
          self.scanner = scanner

      def scan_postgres(self, connection_string: str, table: str,
                       columns: Optional[List[str]] = None,
                       limit: int = 1000) -> ScanResult:
          """Scan PostgreSQL table"""
          try:
              import psycopg2
          except ImportError:
              raise ImportError("Install psycopg2: pip install psycopg2-binary")

          conn = psycopg2.connect(connection_string)
          cursor = conn.cursor()

          # Get columns if not specified
          if not columns:
              cursor.execute(f"""
                  SELECT column_name
                  FROM information_schema.columns
                  WHERE table_name = '{table}'
              """)
              columns = [row[0] for row in cursor.fetchall()]

          # Scan rows
          start_time = datetime.now()
          all_matches = []

          columns_str = ', '.join(columns)
          cursor.execute(f"SELECT {columns_str} FROM {table} LIMIT {limit}")

          rows = cursor.fetchall()
          for row_idx, row in enumerate(rows):
              for col_idx, value in enumerate(row):
                  if value:
                      location = f"{table}.{columns[col_idx]}[row:{row_idx}]"
                      matches = self.scanner.scan_text(str(value), location)
                      all_matches.extend(matches)

          duration_ms = (datetime.now() - start_time).total_seconds() * 1000

          cursor.close()
          conn.close()

          return self._build_result(len(rows), all_matches, duration_ms)

      def _build_result(self, total_scanned: int, matches: List[PIIMatch],
                       duration_ms: float) -> ScanResult:
          """Build scan result summary"""
          summary = {}
          severity_summary = {}

          for match in matches:
              pii_type = match.pii_type.value
              severity = match.severity.value
              summary[pii_type] = summary.get(pii_type, 0) + 1
              severity_summary[severity] = severity_summary.get(severity, 0) + 1

          return ScanResult(
              total_scanned=total_scanned,
              pii_found=len(matches),
              matches=matches,
              summary=summary,
              severity_summary=severity_summary,
              scan_duration_ms=duration_ms
          )


  class FileScanner:
      """Scan files for PII"""

      def __init__(self, scanner: PIIScanner):
          self.scanner = scanner

      def scan_json_file(self, filepath: str) -> ScanResult:
          """Scan JSON file for PII"""
          start_time = datetime.now()

          with open(filepath, 'r') as f:
              data = json.load(f)

          if isinstance(data, list):
              all_matches = []
              for i, item in enumerate(data):
                  matches = self.scanner.scan_dict(item, f"{filepath}[{i}]")
                  all_matches.extend(matches)
              total = len(data)
          elif isinstance(data, dict):
              all_matches = self.scanner.scan_dict(data, filepath)
              total = 1
          else:
              all_matches = []
              total = 0

          duration_ms = (datetime.now() - start_time).total_seconds() * 1000

          return self._build_result(total, all_matches, duration_ms)

      def scan_text_file(self, filepath: str) -> ScanResult:
          """Scan text/log file for PII"""
          start_time = datetime.now()

          with open(filepath, 'r') as f:
              lines = f.readlines()

          all_matches = []
          for line_num, line in enumerate(lines, 1):
              location = f"{filepath}:line{line_num}"
              matches = self.scanner.scan_text(line, location)
              all_matches.extend(matches)

          duration_ms = (datetime.now() - start_time).total_seconds() * 1000

          return self._build_result(len(lines), all_matches, duration_ms)

      def _build_result(self, total_scanned: int, matches: List[PIIMatch],
                       duration_ms: float) -> ScanResult:
          """Build scan result summary"""
          summary = {}
          severity_summary = {}

          for match in matches:
              pii_type = match.pii_type.value
              severity = match.severity.value
              summary[pii_type] = summary.get(pii_type, 0) + 1
              severity_summary[severity] = severity_summary.get(severity, 0) + 1

          return ScanResult(
              total_scanned=total_scanned,
              pii_found=len(matches),
              matches=matches,
              summary=summary,
              severity_summary=severity_summary,
              scan_duration_ms=duration_ms
          )


  class ReportGenerator:
      """Generate compliance reports"""

      @staticmethod
      def generate_json(result: ScanResult, output_file: str):
          """Generate JSON report"""
          with open(output_file, 'w') as f:
              json.dump(result.to_dict(), f, indent=2)
          print(f"JSON report saved to: {output_file}")

      @staticmethod
      def generate_html(result: ScanResult, output_file: str):
          """Generate HTML compliance report"""
          html = f"""
  <!DOCTYPE html>
  <html>
  <head>
      <title>PII Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
      <style>
          body {{ font-family: Arial, sans-serif; margin: 20px; }}
          h1 {{ color: #333; }}
          .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
          .critical {{ color: #d32f2f; font-weight: bold; }}
          .high {{ color: #f57c00; font-weight: bold; }}
          .medium {{ color: #fbc02d; font-weight: bold; }}
          .low {{ color: #388e3c; }}
          table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
          th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
          th {{ background-color: #4CAF50; color: white; }}
          tr:nth-child(even) {{ background-color: #f2f2f2; }}
      </style>
  </head>
  <body>
      <h1>PII Detection Report</h1>

      <div class="summary">
          <h2>Summary</h2>
          <p><strong>Total Items Scanned:</strong> {result.total_scanned}</p>
          <p><strong>PII Occurrences Found:</strong> {result.pii_found}</p>
          <p><strong>Scan Duration:</strong> {result.scan_duration_ms:.2f}ms</p>
          <p><strong>Timestamp:</strong> {datetime.now().isoformat()}</p>
      </div>

      <div class="summary">
          <h2>PII Types Detected</h2>
          <ul>
  """
          for pii_type, count in result.summary.items():
              html += f"            <li><strong>{pii_type}:</strong> {count} occurrences</li>\n"

          html += """        </ul>
      </div>

      <div class="summary">
          <h2>Severity Breakdown</h2>
          <ul>
  """
          for severity, count in result.severity_summary.items():
              css_class = severity.lower()
              html += f'            <li class="{css_class}"><strong>{severity}:</strong> {count} occurrences</li>\n'

          html += """        </ul>
      </div>

      <h2>Detailed Findings</h2>
      <table>
          <tr>
              <th>Severity</th>
              <th>PII Type</th>
              <th>Location</th>
              <th>Context</th>
              <th>Timestamp</th>
          </tr>
  """
          for match in result.matches:
              css_class = match.severity.value.lower()
              html += f"""        <tr>
              <td class="{css_class}">{match.severity.value}</td>
              <td>{match.pii_type.value}</td>
              <td><code>{match.location}</code></td>
              <td><code>{match.context[:100]}...</code></td>
              <td>{match.timestamp}</td>
          </tr>
  """

          html += """    </table>
  </body>
  </html>
  """

          with open(output_file, 'w') as f:
              f.write(html)
          print(f"HTML report saved to: {output_file}")

      @staticmethod
      def print_console(result: ScanResult):
          """Print report to console"""
          print("\n" + "="*80)
          print("PII SCAN REPORT")
          print("="*80)
          print(f"Total items scanned: {result.total_scanned}")
          print(f"PII occurrences found: {result.pii_found}")
          print(f"Scan duration: {result.scan_duration_ms:.2f}ms")
          print(f"Timestamp: {datetime.now().isoformat()}")

          if result.summary:
              print("\nPII Types Detected:")
              for pii_type, count in sorted(result.summary.items()):
                  print(f"  - {pii_type}: {count}")

          if result.severity_summary:
              print("\nSeverity Breakdown:")
              for severity, count in sorted(result.severity_summary.items()):
                  print(f"  - {severity}: {count}")

          if result.matches:
              print(f"\nShowing first 10 matches (total: {len(result.matches)}):")
              for i, match in enumerate(result.matches[:10], 1):
                  print(f"\n  [{i}] {match.severity.value} - {match.pii_type.value}")
                  print(f"      Location: {match.location}")
                  print(f"      Context: {match.context[:80]}...")

          print("\n" + "="*80)


  def main():
      parser = argparse.ArgumentParser(
          description='PII Scanner - Detect PII in databases, files, and text'
      )

      # Data source options
      parser.add_argument('--db', help='Database connection string (postgres://...)')
      parser.add_argument('--table', help='Database table name')
      parser.add_argument('--columns', nargs='+', help='Columns to scan (default: all)')
      parser.add_argument('--file', help='File to scan (JSON or text)')
      parser.add_argument('--stdin', action='store_true', help='Read from stdin')

      # Scan options
      parser.add_argument('--strict', action='store_true', default=True,
                         help='Strict mode (default: true)')
      parser.add_argument('--limit', type=int, default=1000,
                         help='Max rows to scan (default: 1000)')

      # Output options
      parser.add_argument('--output', help='Output file (JSON or HTML based on extension)')
      parser.add_argument('--format', choices=['json', 'html', 'console'],
                         default='console', help='Output format')

      args = parser.parse_args()

      # Initialize scanner
      scanner = PIIScanner(strict_mode=args.strict)

      # Execute scan
      if args.db and args.table:
          db_scanner = DatabaseScanner(scanner)
          result = db_scanner.scan_postgres(args.db, args.table, args.columns, args.limit)
      elif args.file:
          file_scanner = FileScanner(scanner)
          if args.file.endswith('.json'):
              result = file_scanner.scan_json_file(args.file)
          else:
              result = file_scanner.scan_text_file(args.file)
      elif args.stdin:
          text = sys.stdin.read()
          matches = scanner.scan_text(text, "stdin")
          result = ScanResult(
              total_scanned=1,
              pii_found=len(matches),
              matches=matches,
              summary={m.pii_type.value: 1 for m in matches},
              severity_summary={m.severity.value: 1 for m in matches},
              scan_duration_ms=0
          )
      else:
          parser.print_help()
          sys.exit(1)

      # Generate output
      if args.output:
          if args.output.endswith('.html'):
              ReportGenerator.generate_html(result, args.output)
          else:
              ReportGenerator.generate_json(result, args.output)
      elif args.format == 'html':
          ReportGenerator.generate_html(result, 'pii_report.html')
      elif args.format == 'json':
          ReportGenerator.generate_json(result, 'pii_report.json')
      else:
          ReportGenerator.print_console(result)


  if __name__ == '__main__':
      main()
