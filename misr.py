# Ali Essam
# https://www.facebook.com/AliElTop313
# https://www.linkedin.com/in/dragonked2
# https://www.github.com/dragonked2
import asyncio
import logging
import re
from urllib.parse import urlparse, urljoin, quote
import aiofiles
import aiohttp
from tqdm import tqdm
from colorama import Fore, Style, init
from pyfiglet import Figlet
from bs4 import BeautifulSoup
from async_lru import alru_cache
from difflib import SequenceMatcher

# De El Configuration
PAYLOAD_FILE = "payloads.txt"
OUTPUT_FILE = "vulnerable_urls.txt"
SECRETS_FILE = "secrets.txt"
TIMEOUT = 30
MAX_CONNECTIONS = 100
CRAWL_DEPTH = 3
SIMILARITY_THRESHOLD = 0.9
MAX_RETRIES = 3


init(autoreset=True)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


MATRIX_GREEN = Fore.GREEN + Style.BRIGHT
MATRIX_BLUE = Fore.BLUE + Style.BRIGHT
MATRIX_YELLOW = Fore.YELLOW + Style.BRIGHT


# Lets Go Egypt :*
class BugBountyHunter:
    def __init__(self):
        self.visited_urls = set()
        self.vulnerable_urls = set()
        self.secrets = set()

    async def run_command(self, command):
        try:
            proc = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
        except asyncio.CancelledError:
            logging.error("Command execution cancelled.")
        except Exception as e:
            logging.error(f"Error executing command '{command}': {e}")

    async def extract_urls_from_page(self, url, session, target_domain):
        urls = set()
        try:
            async with session.get(url, timeout=TIMEOUT) as response:
                if response.status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "text/html" in content_type:
                        soup = BeautifulSoup(await response.text(), "html.parser")
                        for link in soup.find_all("a", href=True):
                            href = link.get("href")
                            absolute_url = urljoin(url, href)
                            if not any(
                                self.similar(absolute_url, u) > SIMILARITY_THRESHOLD
                                for u in self.visited_urls
                            ):
                                urls.add(absolute_url)
                    elif "javascript" in content_type:
                        js_content = await response.text(
                            encoding="utf-8", errors="ignore"
                        )
                        js_urls = re.findall(
                            r'(?<=href=["\'])https?://[^\s\'"]+',
                            js_content,
                            re.IGNORECASE,
                        )
                        urls.update(js_urls)
                    elif "json" in content_type:
                        json_content = await response.text(
                            encoding="utf-8", errors="ignore"
                        )
                        json_urls = re.findall(r'(?<="url":\s*")[^"]+', json_content)
                        urls.update(json_urls)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            #logging.error(f"Error extracting URLs from {url}: {e}")
            pass
        return urls
        

    async def crawl_website(self, url, depth, target_domain, session, progress_bar):
        if (
            depth <= 0
            or url in self.visited_urls
            or not self.is_valid_url(url, target_domain)
        ):
            return set()

        self.visited_urls.add(url)
        valid_urls = set()

        try:
            async with session.get(url, timeout=TIMEOUT) as response:
                if response.status == 200:
                    content_type = response.headers.get("Content-Type", "")
                    if "text/html" in content_type:
                        urls = await self.extract_urls_from_page(
                            url, session, target_domain
                        )
                        valid_urls.update(
                            u for u in urls if self.is_valid_url(u, target_domain)
                        )
                    tasks = [
                        self.crawl_website(
                            u, depth - 1, target_domain, session, progress_bar
                        )
                        for u in valid_urls
                    ]
                    nested_results = await asyncio.gather(*tasks)
                    for result in nested_results:
                        valid_urls.update(result)
                else:
                    logging.warning(
                        f"Failed to crawl {url}. Status code: {response.status}"
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"Error crawling {url}: {e}")

        progress_bar.update(1)
        return valid_urls

    async def check_vulnerability(self, url, session, progress_bar):
        vulnerabilities = {
            "Regex Detected": [
                "AliElTop",
                "13337777",
                "www-data",
                "Bash:",
                "root:",
                "oastify.com",
            ],
            "Sqli": [
                "SQL syntax error",
                "You have an error in your SQL syntax",
                "MySQL server version",
                "Warning: mysql_fetch_array() expects parameter",
                "Microsoft OLE DB Provider for ODBC Drivers error",
                "Unclosed quotation mark before the character string",
                "ORA-00921: unexpected end of SQL command",
                "Microsoft SQL Native Client error",
                "PostgreSQL query failed",
                "SQLite3::exec(): near",
            ],
            "root:": [
                "Command not found",
                "sh: command not found",
                "Unable to fork",
                "Permission denied (publickey)",
                "Access denied for user",
                "PHP Parse error",
                "Syntax error, unexpected",
                "Error: execution failed",
                "Not a recognized command",
                "Exited with error code",
            ],
            "13337777": [
                "alert('XSS')",
                "Cross-Origin Request Blocked",
                "Refused to execute inline script",
                "Uncaught SyntaxError: Unexpected token",
                "Error: Access is denied",
                "Unsafe JavaScript attempt to access",
                "SecurityError: Blocked a frame with origin",
                "XSS Filter - Bad Request",
            ],
            "Bash:": [
                "Failed to open stream: No such file or directory",
                "Warning: include(): Failed opening",
                "Unable to include",
                "failed to open stream: Permission denied",
                "file not found",
                "File does not exist",
                "No such file or directory in",
                "Failed to open stream: No such file or directory",
                "Warning: include(): Failed opening",
                "Unable to include",
                "failed to open stream: Permission denied",
                "file not found",
                "File does not exist",
                "No such file or directory in",
                "status:Success",
                "auth:false",
                "cast_build_revision:",
                "ssdp_udn:",
                "><script>alert(1)</script>",
                "id:",
                "version:",
                "method:",
                "url:",
                "time:",
                "instance_metadata:",
                "cloud:",
                "username:",
                "loginName:",
                "password:",
                "pre_define",
                "auth_method",
                "name",
                "password",
                "reason:",
                "success",
                "antiadwa:",
                "clientupgrade:",
                "autoCount",
                "autoGet",
                "cf_main_cf src=javascript:alert(1)",
                "?pgid=User_Show",
                "api_keys:",
                "aws:",
                "server:",
                "couchbase:",
                "bucket:",
                "data:",
                "client_secret:",
                "client_id:",
                "><script>alert(document.domain)</script>",
                "></script><script>alert(document.domain)</script>",
                "><script>alert(document.domain)</script>",
                "ok:true",
                "data",
                "repolink:",
                "></script><script>alert(document.domain)</script>",
                "><script>alert(document.domain);</script><",
                "></script><script>alert(document.domain)</script>",
                "id:",
                "name:",
                "avatar_urls:",
                "><script>alert(document.domain);</script><",
                "version:",
                "serial_number:",
                "><script>prompt(document.domain)</script>.xrf",
                "message:An internal server error occurred",
                "><script>alert(/{{randstr}}/);</script>",
                "><script>alert(document.domain)</script>&really_del=1>YES",
                "><script>alert(document.domain)</script></a>",
                "><script>alert(document.domain)</script></a>",
                "><script>alert(document.domain)</script></a>",
                "date:",
                "message:",
                "trace:[",
                "><script>alert(1)</script>",
                "uid:",
                "pwd:",
                "view:",
                "user_login",
                "user_pass",
                "user_nicename",
                "</script><script>alert(document.domain);</script><script>",
                "deleteUrl:",
                "deleteKey:",
                "key:",
                "url:",
                "name:admin",
                "admin:true",
                "username:",
                "email:",
                "jwt:",
                "results:",
                "name:databases",
                "</script><script>alert(document.domain)</script>><input",
                "username: access-admin",
                ";alert('1');//",
                "deleteKey:",
                "deleteUrl:",
                "dag_run_url:",
                "dag_id:",
                "items:",
                "action:create",
                "script:",
                "node:",
                "user_login",
                "user_email",
                "user_pass",
                "user_activation_key",
                "groups:",
                "><script>alert(document.domain)</script>",
                "/></script><script>alert(document.domain)</script>",
                "alarm_model",
                "actions",
                "severity",
                "username:",
                "avatarUrl:",
                "node:",
                "(guid|title|content|excerpt):{rendered:",
                "clientId:security-admin-console",
                "secret:",
                "username:",
                "email:",
                "status:",
                "result\\:false",
                "success:true",
                "></script><script>alert(document.domain)</script>",
                "type",
                "id_user",
                "user_name",
                "text",
                "jsonrpc:",
                "filename:",
                "status : 400",
                "zlo onerror=alert(1)",
                "zlo onerror=alert(1)",
                "zlo onerror=alert(1)",
                "success:true",
                "success:true",
                "nonce:[a-f0-9]+",
                "service_id",
                "style=animation-name:rotation onanimationstart=alert(document.domain) x",
                "guppyUsers:",
                "userId:",
                "type:",
                "style=animation-name:rotation onanimationstart=alert(document.domain) x",
                "additional_fields:[<img src=x onerror=alert(document.domain)>]}",
                "path:(.*)/wp-content\\\\(.*),size",
                "></script><script>alert(document.domain)</script>",
                "></script><script>alert(document.domain)</script>.php",
                "deleteUrl:",
                "deleteKey:",
                "results:",
                "name:",
                "tab:",
                "TABLENAME:(?:(?:(?:(?:(?:APP_CONFIGDATA_RELATION_[PS]UB|SYS(?:(?:CONGLOMERAT|ALIAS|(?:FI|RO)L)E|(?:(?:ROUTINE)?|COL)PERM|(?:FOREIGN)?KEY|CONSTRAINT|T(?:ABLEPERM|RIGGER)|S(?:TAT(?:EMENT|ISTIC)|EQUENCE|CHEMA)|DEPEND|CHECK|VIEW|USER)|USER|ROLE)S|CONFIG_(?:TAGS_RELATION|INFO_(?:AGGR|BETA|TAG))|TENANT_CAPACITY|GROUP_CAPACITY|PERMISSIONS|SYSCOLUMNS|SYS(?:DUMMY1|TABLES)|APP_LIST)|CONFIG_INFO)|TENANT_INFO)|HIS_CONFIG_INFO)",
                "><script>alert({{randstr}})</script>",
                "><script>alert(document.domain)</script>",
                "result:true",
                "k3woq^confirm(document.domain)^a2pbrnzx5a9",
                "><h1>Test</h1>26 class=loginUserNameText",
                "HTTP_X_TRIGGER_XSS:<script>alert(1)</script>",
                "traces:[",
                "headers",
                "request:{",
                "userName:admin",
                "code:200",
                "uuid:",
                "glpi:",
                "isSnapshot:true",
                "TYPE",
                "ITEMS",
                "COUNT",
                "pbx",
                "dongleStatus:0",
                "macaddr",
                "subTitle:Grafana (v8\\.(?:(?:1|0)\\.[0-9]|2\\.[0-2]))",
                "data",
                "users",
                "nodes",
                "id",
                "success:true",
                "msg:success",
                "rc:(.*?)",
                "msg:(.*?)",
                "success:true",
                "account:",
                "password:",
                "Consumers:",
                "></script><script>alert(document.domain)</script>",
                "Date Submitted",
                "Entries ID",
                "background:",
                "footer:",
                "current_currency:",
                "username:",
                "email:",
                "display_name:",
                "status:success",
                "appointments:",
                "unavailables:",
                "First Name",
                "success:1",
                "id:",
                "rendered:",
                "<script>alert(document.domain)</script>,",
                "payment_confirmation_message:",
                "page:",
                "results:",
                "success:true",
                "isGuest:true",
                "accessToken:",
                "uname:",
                "upassword:",
                "user_name;",
                "user_pwd;",
                "user_id;",
                "email:([a-zA-Z-_0-9@.]+),display_name:([a-zA-Z-_0-9@.]+),gravatar_url:http?:\\\\\\/\\\\\\/([a-z0-9A-Z.\\\\\\/?=&@_-]+)",
                "departments:",
                "name:",
                "registration_no:",
                "></script><script>alert(document.domain)</script>",
                "message:query success",
                "code:200",
                "reason:OK",
                "status:200",
                "success:true",
                "type:error,text:Unknown survey\\><img src=x onerror=alert(document.domain)>",
                "<wps:LiteralData>dest = y() - (500); // */ public class Double {    public static double NaN = 0;  static { try {  java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(cat /etc/passwd).getInputStream())); String line = null; String allLines =  - ; while ((line = reader.readLine()) != null) { allLines += line; } throw new RuntimeException(allLines);} catch (java.io.IOException e) {} }} /**</wps:LiteralData>",
                "></script><script>alert(document.domain)</script>",
                "Not authenticated",
                "((firmware|(version|ma(sk|c)|port|url|ip))|hostname):",
                "Success: true",
                "Success:true",
                "zabbix:",
                "zbx:",
                "password:(.*?)",
                "username:(.*?)",
                "status:",
                "data:",
                "token:",
                "clientid:",
                "Chat Log",
                "User IP",
                "User ID",
                "res_msg:Authentication Success.",
                "doc_id:user_systemi",
                "username:",
                "password:",
                "mustChangePwd:",
                "roleUser:",
                "><script>alert(document.domain)</script>",
                "><script>alert(document.domain)</script>",
                "plmnID:",
                "ueId:",
                "jiraGroupObjects",
                "groupName",
                "registered:",
                "display_name:",
                "value:",
                "local_data_id:",
                "status:",
                "pagination:",
                "img:",
                "date:",
                "title:",
                "params:",
                "license:",
                "name:",
                "errorMessage:Internal error",
                "password:",
                "isAdmin:",
                "createAt:",
                "apiVersion:",
                "uuid:",
                "userName:",
                "status:OK",
                "sessionid:",
                "mode:",
                "links:",
                "attributes:",
                "CVE-2023-25135",
                "slug:",
                "name:",
                "ip_address",
                "database_name:",
                "configuration_method:",
                "registered_date:",
                "username:",
                "email:",
                "MINIO_ROOT_PASSWORD:",
                "MINIO_ROOT_USER:",
                "MinioEnv:",
                "success:true",
                "data:null",
                "{source_id: test'; copy (SELECT '') to program '{{cmd}}'-- - }",
                "username:",
                "name:",
                "email:",
                "role:",
                "name",
                "version",
                "ghost",
                "success:true",
                "data:",
                "username:",
                "email:",
                "roles:",
                "database_name:",
                "database_user:",
                "original_fileName:",
                "converted_fileName:",
                "refresh_token",
                "access_token",
                "token_type",
                "expires_in",
                "success:200",
                "message:ok",
                "success:200",
                "message:ok",
                "is_dir:",
                "path:",
                "files:",
                "result:ok",
                "terminal:",
                "user_id:",
                "account_id:",
                "result:ok",
                "msg:登入成功",
                "{{string}}><script>alert(document.domain)</script>",
                "form_id:{{form_id}}",
                "behav",
                "responseHeader:",
                "solr.jetty:",
                ");alert(document.domain);//",
                "Authorized:false",
                "registered_model:",
                "name:",
                "><script>alert(document.domain)</script> />",
                "id:",
                "question_type:",
                "points_total:",
                "id:",
                "id:",
                "quiz_materials:",
                "result:",
                "message:",
                "password:",
                "softAp:",
                "link:file:",
                "success:",
                "access_token:",
                "token_type:",
                "success:true",
                "token:",
                "folders: {",
                "connection-types: {",
                "connections: {",
                "memstats:",
                "cmdline:",
                "authResult:0",
                "droplet_id:",
                "hostname:",
                "repositories:",
                "email:",
                "auth:",
                "msg:login success",
                "sessionId:",
                "message:The username does not exist",
                "authorizationNeeded: false",
                ":a.",
                ":A.",
                "text:<img src=x onerror=alert(document.domain)>",
                "code:",
                "detailMsg:",
                "data:true",
                "sessionkey:",
                "message:",
                "took:",
                "number :",
                "number_of_nodes",
                "roles",
                "permissions",
                "role",
                "kv",
                "etcdserver",
                "etcdcluster",
                "auth:",
                "success: true",
                "status :true",
                "connection",
                "name",
                "driver",
                "password",
                "url",
                "user",
                "loginRes:success",
                "activeUserName:cmuser",
                "msg:ok",
                "type:",
                "NoAuth:true",
                "/licenses/NOTICE.txt",
                "/vpn/resources/{lang}",
                "/lanproxy-config/",
                "theme:group-office,",
                "/cnf/r/cms/common.js",
                "generator content=Microweber />",
                "success",
                "hash:<img src=x onerror=alert(document.domain)>",
                "errors",
                "product:",
                "proxies:",
                "protocol:",
                "host:",
                "user:",
                "provision:",
                "provisionArgs:",
                "access_token:",
                "token_type:",
                "- (?m)^\\s*- ?uses?:",
                "access_token:",
                "token_type:",
                "refresh_token:",
                "0nuboard<svg onload=alert(document.domain)>",
                "clientId",
                "clientVersion",
                "gpc",
                "data:",
                "{{str}}1:",
                "{{str}}6:",
                "query",
                "data",
                "__typename",
                "username",
                "authToken",
                "guacadmin",
                "/bin",
                "__meta:",
                "schema_name:",
                "profile",
                "application-id",
                "auth_mode",
                "harbor_version",
                "Datacenter:",
                "Revision:",
                "PrimaryDatacenter",
                "username:{{user}}",
                "code:",
                "msg:",
                "success:true",
                "resourceName:",
                "name:",
                "length:",
                "filePath:",
                "list:",
                "redirect: /htdocs/pages/main/main.lsp",
                "error:",
                "site-name>iClock Automatic Data Master Server",
                "PUBLIC_IMMICH_",
                "exitcode:0",
                "access:read",
                "access:readwrite",
                "loginSucceeded:true",
                "baseUrl",
                "deploymentType",
                "id:",
                "name:",
                "description:",
                "timestamp:",
                "protocol:",
                "agent:",
                "mbean:java.lang:type=Memory",
                "attribute:ImplementationVendor",
                "attribute:ImplementationVersion",
                "attribute:ImplementationName",
                "attribute:SpecificationVendor",
                "attribute:MBeanServerId",
                "attribute:SpecificationName",
                "attribute:SpecificationVersion",
                "type:list",
                "type:search",
                "value:",
                "name:",
                "username:",
                "email:",
                "value:passwd",
                "value:group",
                "disable:false",
                "expire_time:",
                "jsapi_ticket:",
                "compilerOptions: {",
                "typeAcquisition: {",
                "id:",
                "settings",
                "schema:",
                "name:",
                "last_activity:",
                "code:200",
                "name:admin",
                "html_title: Kasm",
                "ConnectionStrings:",
                "Path:",
                "TokenKey:",
                "result:true",
                "DeploymentList:",
                "items:",
                "NamespaceList:",
                "items:",
                "NodeList:",
                "items:",
                "containerRuntimeVersion",
                "kubeletVersion: v",
                "PodList:",
                "items:",
                "SecretList:",
                "items:",
                "ServiceList:",
                "items:",
                "major:",
                "minor:",
                "goVersion:",
                "PodList:",
                "items:",
                "PodList:",
                "items:",
                "node:",
                "nodeName:",
                "userDetails:",
                "username:",
                "password:",
                "1106649083 == mmh3(base64_py(body))",
                "changes:",
                "resources:",
                "PRODUCT_NAME:ManageEngine ADSelfService",
                "m\\.([a-z]+):",
                "server:",
                "name:",
                "version:",
                "><img src onerror=alert(document.domain) x",
                "data:",
                "success:true",
                "generator content=Microweber />",
                "><script>javascript:alert(document.cookie)</script>",
                "ParentId:",
                "Containers:",
                "Labels:",
                "totalCount:",
                "username:",
                "password:",
                "pagesAvailable:",
                "username:",
                "password:",
                "accessToken:",
                "username:",
                "version:(\\d+\\.\\d+\\.\\d+)",
                "response: ok,",
                "message: Welcome.",
                "versionstring:",
                "installed:",
                "edition:",
                "metricId:",
                "metrics:",
                "successfulInstalls:",
                "metricId",
                "metrics",
                "VerifyKey:",
                "msg: login success",
                "status: 1",
                "plugin:",
                "pluginCode:",
                "id:",
                "type: success",
                "client_id:",
                "client_secret:",
                "application_title:oVirt Engine User Portal",
                "application_title:oVirt Engine Web Administration",
                "schema_version:",
                "name_for_model:",
                "title:OpenEMR Product Registration",
                "authenticated:true",
                "permissions:",
                "bulk_",
                "archived_snapshots: {closest",
                "archived_snapshots: {closest",
                "description :The Pega API",
                "version:",
                "indent:",
                "id:",
                "datetime:",
                "method",
                "defects",
                "pipfile-spec:",
                "requires",
                "username:",
                "status: success:",
                "data:",
                "yaml:",
                "data:",
                "config.file:",
                "status: success",
                "data:",
                "labels:",
                "version\\s:\\s([0-9.]+)",
                "Action:AdminLogin",
                "Result:true",
                "statusCode:200",
                "msgDesc:Login Successful",
                "firstName",
                "><script>alert(document.domain)</script>",
                "data:",
                "status:1",
                "role:super_admin,name:(.*),password:(.*)",
                "http_username:",
                "http_passwd:",
                "LoginOK:ok",
                "success:",
                "private_key_id:",
                "private_key:",
                "isValid:true",
                "count:",
                "display_value:(.*),",
                "host:",
                "user:",
                "password:",
                "remote_path:",
                "host:",
                "username:",
                "password:",
                "remotePath:",
                "username:showdoc",
                "user_token:",
                "username:",
                "email:",
                "isTopTeacher:",
                "result:true",
                "retCode:0",
                "H~CxOm~",
                "visibility:public",
                "results:",
                "items:",
                "more:",
                "contentsServer:",
                "networkInterfaces:",
                "serverTime:",
                "hostIp:",
                "status:999",
                "_links:",
                "self:",
                "health",
                "type",
                "beans",
                "dependencies",
                "scope",
                "positiveMatches:{",
                "unconditionalClasses:[",
                "enabled:[",
                "disabled:[",
                "spring.datasource.hikari.connection-test-query:CREATE ALIAS EXEC AS CONCAT",
                "status",
                "diskSpace",
                "jms",
                "traces",
                "timestamp",
                "principal",
                "session",
                "build",
                "artifact",
                "config:{",
                "agentId:",
                "FILENAME:",
                "propertySources",
                "loggers",
                "levels",
                "freeMemory:",
                "maxMemory:",
                "threads:",
                "threadName:",
                "timestamp",
                "info",
                "method",
                "path",
                "user:",
                "token:",
                "expiry:",
                "data",
                "uuid",
                "hasAdmin",
                "providerId",
                "swagger:",
                "suc:true",
                "msg:\\u6210\\u529f",
                ">Chamilo ([\\d.]+)</a>",
                "client_id:",
                "user_name:",
                "access_token:",
                "token_type:",
                "root@",
                "para:",
                "td_oa",
                "dept_name:",
                "online_flag:",
                "auth_token:",
                "organization_id:",
                "state:SUCCESS",
                "success :",
                "sid :",
                "authorized:true",
                "><script>alert(document.domain)</script>",
                "archived_snapshots: {closest",
                "archived_snapshots: {closest",
                "original:",
                "SUCCESS",
                "token:",
                "username:",
                "node:",
                "key:",
                "{\\msg\\:\\result\\,\\result\\:{\\messages\\",
                "success:true",
                "username:anonymous",
                "Administrator",
                "newPassword:",
                "status: ok",
                "userName",
                "name:",
                "host:",
                "protocol:",
                "fullyQualifiedName",
                "logonDomain",
                "username",
                "password",
                "username:",
                "roles:",
                "status:true}",
                "version:",
                "file:",
                "sources:",
                "db-password:",
                "db-database:",
                "><script>confirm(document.domain)</script>",
                "success:true",
                "data:",
                "filepath",
                "status",
                "hava",
                "degree",
                "icon",
                "id:",
                "name:",
                "avatar_urls:",
                "><script>alert(document.domain)</script>",
                "><script>alert(document.domain)</script>",
                "appName:X Prober",
                "success:true",
                "code:200",
                "msg",
                "content",
                "username:{{user}}",
                "kyc_status:",
                "redirection]",
                "param",
                "sessionName:zentaosid",
                "name:",
                "projects:",
                "queue:",
            ],
            "root:": [
                "Command not found",
                "sh: command not found",
                "Unable to fork",
                "Permission denied (publickey)",
                "Access denied for user",
                "PHP Parse error",
                "Syntax error, unexpected",
                "Error: execution failed",
                "Not a recognized command",
                "Exited with error code",
            ],
            "XSS": [
                "alert('13337777')",
                "Cross-Origin Request Blocked",
                "Refused to execute inline script",
                "Uncaught SyntaxError: Unexpected token",
                "Error: Access is denied",
                "Unsafe JavaScript attempt to access",
                "SecurityError: Blocked a frame with origin",
                "XSS Filter - Bad Request",
            ],
            "LFI or RFI": [
                "Failed to open stream: No such file or directory",
                "Warning: include(): Failed opening",
                "Unable to include",
                "failed to open stream: Permission denied",
                "file not found",
                "File does not exist",
                "No such file or directory in",
            ],
            "LFI": [
                "Failed to open stream: No such file or directory",
                "Warning: include(): Failed opening",
                "Unable to include",
                "failed to open stream: Permission denied",
                "file not found",
                "File does not exist",
                "No such file or directory in",
            ],
        }

        content_types_to_check = [
            "text/html",
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "application/octet-stream",
        ]

        with open(PAYLOAD_FILE, "r", encoding="utf-8", errors="ignore") as f:
            payloads = f.read().splitlines()

        for payload in payloads:
            modified_url = url + quote(payload)
            try:
                async with session.get(modified_url, timeout=TIMEOUT) as response:
                    if response.status == 200:
                        content_type = response.headers.get("Content-Type", "").split(
                            ";"
                        )[0]
                        if content_type not in content_types_to_check:
                            continue  # hn3mel hena Skip law el content type mesh fe el lista
                        text = await response.text(encoding="utf-8", errors="ignore")
                        for vuln_type, patterns in vulnerabilities.items():
                            for pattern in patterns:
                                if re.search(pattern, text, re.IGNORECASE):
                                    logging.warning(
                                        f"Vulnerability found: {modified_url} ({vuln_type})"
                                    )
                                    if modified_url not in self.vulnerable_urls:
                                        await self.save_to_file(
                                            OUTPUT_FILE,
                                            f"{modified_url} ({vuln_type})\n",
                                        )
                                        self.vulnerable_urls.add(modified_url)
                                    break
            except (aiohttp.ClientError, UnicodeError, asyncio.TimeoutError) as e:
                # logging.error(f"Error checking {modified_url}: {e}")
                pass

        progress_bar.update(1)

    async def find_secrets(self, url, session):
        secret_patterns = {
            "Passwords": r"\b(?:[pP][a@]ss[wW]ord(?:s|)|[pP][a@]ss[wW][0oO]rd|pass[wW]d|passcode|secret|admin|root|123456|qwerty)\b\s*[:=]\s*([^\s]+)",
            "API Keys": r"\b(?:[A-Za-z0-9]{20,50}|[A-Za-z0-9]{8}-(?:[A-Za-z0-9]{4}-){3}[A-Za-z0-9]{12}|[A-Za-z0-9]{32}|[A-Za-z0-9]{30}-[A-Za-z0-9]{10}|[A-Za-z0-9]{27}-[A-Za-z0-9]{27})\b",
            "Email Addresses": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "AWS Credentials": r"\b(?:AKIA|ASIA|AGPA)[A-Z0-9]{16}\b",
            "JWT Tokens": r"\beyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b",
            "SSH Keys": r"\b(?:ssh-(?:rsa|dsa|ecdsa|ed25519))\s+[^\s]+(?:\s+[^\s]+){1,2}\b",
            "Private Keys (Crypto)": r"\b(?:-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)[\s\S]+?(?:-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)\b",
            "Credit Card Numbers": r"\b(?:4[0-9]{3}(?:[ -]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[ -]?[0-9]{4}){3}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})(?:[ -]?[0-9]{4}){3}|(?:2131|1800|35\d{3})(?:[ -]?[0-9]{4}){3})\b",
            "Social Security Numbers": r"\b(\d{3}-\d{2}-\d{4})\b",
            "Phone Numbers": r"\b(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
            "URLs": r"\b(?:https?|ftp):\/\/[\w-]+(\.[\w-]+)+\S*(?::\d{2,5})?(?:\/\S*)?\b",
            "IPv4 Addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "IPv6 Addresses": r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b",
            "MAC Addresses": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
            "Dates": r"\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b",
            "Bank Account Numbers": r"\b(?:\d{4}\s?){3,4}\b",
            "Domain Names": r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
            "Biometric Data": r"\b(?:fingerprint|retina|iris|voiceprint)\b",
            "Passport Numbers": r"\b[A-Z]{2}\d{7}\b",
            "Health Insurance Numbers": r"\b[A-Z]{3}\d{9}\b",
            "Vehicle Identification Numbers (VIN)": r"\b(?:[A-HJ-NPR-Z\d]{17})\b",
            "Tax Identification Numbers (TIN)": r"\b(?:\d{3}-\d{2}-\d{4})\b",
            "Medical Record Numbers": r"\b(?:[A-Za-z0-9]{5,10})\b",
            "Customer Account Numbers": r"\b(?:[A-Za-z0-9]{6,12})\b",
            "MySQL Connection Strings": r"\b(?:mysql:\/\/(?:[\w\d]+):(?:[\w\d]+)@(?:[\w\d.-]+):(?:\d+)\/(?:[\w\d]+)\b)",
            "MySQL Host": r"\b(?:MYSQL_HOST=)([^\s]+)",
            "MySQL User": r"\b(?:MYSQL_USER=)([^\s]+)",
            "MySQL Password": r"\b(?:MYSQL_PASSWORD=)([^\s]+)",
            "MySQL Database": r"\b(?:MYSQL_DATABASE=)([^\s]+)",
            "Bitcoin Private Keys": r"\b(?:[A-Fa-f0-9]{64}|5[HJK][1-9A-Za-z]{49,50}|K[\dA-Za-z]{51}|L[\dA-Za-z]{51}|[A-Fa-f0-9]{64})\b",
            "Ethereum Private Keys": r"\b0x[a-fA-F0-9]{64}\b",
            "Binance Coin Private Keys": r"\b(?:B[CFGHJ-NP-TV-Z0-9]{50})\b",
            "XRP Private Keys": r"\b(?:s[1-9A-HJ-NP-Za-km-z]{33})\b",
            "TRON Private Keys": r"\b(?:T[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{33})\b",
            "64-Character Hex Private Keys": r"\b(?:[A-Fa-f0-9]{64})\b",
        }

        try:
            async with session.get(url, timeout=TIMEOUT) as response:
                if response.status == 200:
                    text = await response.text(encoding="utf-8", errors="ignore")
                    for secret_type, pattern in secret_patterns.items():
                        secrets = re.findall(pattern, text, re.IGNORECASE)
                        if secrets:
                            for secret in secrets:
                                self.secrets.add((secret_type, secret, url))
        except (aiohttp.ClientError, UnicodeError, asyncio.TimeoutError) as e:
            logging.error(f"Error checking secrets on {url}: {e}")

    async def save_to_file(self, file_path, content):
        async with aiofiles.open(file_path, mode="a", encoding="utf-8") as file:
            await file.write(content)

    async def count_lines(self, file_path):
        try:
            async with aiofiles.open(file_path, mode="r", encoding="utf-8") as file:
                count = 0
                async for _ in file:
                    count += 1
                return count
        except FileNotFoundError:
            return 0

    async def collect_target_list(self, domain):
        try:
            await self.run_command(f"subfinder -d {domain} -o subdomains.txt")
            await self.run_command(f"httpx -l subdomains.txt -o alive_subdomains.txt")
            with open(
                "alive_subdomains.txt", "r", encoding="utf-8", errors="ignore"
            ) as file:
                target_list = [line.strip() for line in file]
            return target_list
        except Exception as e:
            logging.error(f"Error collecting target list: {e}")

    async def main(self):
        print(MATRIX_BLUE + Figlet(font="slant").renderText("Misr"))

        try:
            option = input(
                MATRIX_YELLOW
                + "Do you want to scan a single website or enter a domain name to extract subdomains? (1/2): "
            )
            if option == "1":
                website_url = input(MATRIX_YELLOW + "Enter the website URL: ")
                target_list = [website_url]
            elif option == "2":
                domain = input(MATRIX_YELLOW + "Enter the domain name: ")
                target_list = await self.collect_target_list(domain)
                if not target_list:
                    logging.error("No target list could be generated. Exiting.")
                    return
            else:
                logging.error("Invalid option. Exiting.")
                return

            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=MAX_CONNECTIONS)
            ) as session:
                print(
                    MATRIX_YELLOW
                    + f"\nCrawling websites for all content and links with a depth of {CRAWL_DEPTH}...\n"
                )
                progress_bar = tqdm(
                    total=len(target_list),
                    desc=MATRIX_BLUE + "Crawl Progress",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
                )
                crawled_urls = set()
                for target in target_list:
                    urls = await self.crawl_website(
                        target,
                        CRAWL_DEPTH,
                        urlparse(target).hostname,
                        session,
                        progress_bar,
                    )
                    crawled_urls.update(urls)

                if not crawled_urls:
                    logging.error("No URLs were collected. Exiting.")
                    return

                print(MATRIX_BLUE + "\nChecking for vulnerabilities...\n")
                progress_bar = tqdm(
                    total=len(crawled_urls),
                    desc=MATRIX_BLUE + "Vulnerability Check Progress",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
                )
                try:
                    tasks = [
                        self.check_vulnerability(url, session, progress_bar)
                        for url in crawled_urls
                    ]
                    await asyncio.gather(*tasks)
                except KeyboardInterrupt:
                    logging.error("\nScan interrupted by user.")

                progress_bar.close()
                print(
                    MATRIX_GREEN
                    + f"\nVulnerability checks completed. For more details, check {OUTPUT_FILE}"
                )

                total_vulnerabilities = await self.count_lines(OUTPUT_FILE)
                print(
                    MATRIX_GREEN
                    + f"\nTotal Vulnerabilities Found: {total_vulnerabilities}"
                )

                print(MATRIX_BLUE + "\nSearching for secrets...\n")
                progress_bar = tqdm(
                    total=len(crawled_urls),
                    desc=MATRIX_BLUE + "Secrets Search Progress",
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
                )
                try:
                    tasks = [self.find_secrets(url, session) for url in crawled_urls]
                    await asyncio.gather(*tasks)
                except KeyboardInterrupt:
                    logging.error("\nSecrets search interrupted by user.")

                progress_bar.close()
                print(
                    MATRIX_GREEN
                    + f"\nSecrets search completed. For more details, check {SECRETS_FILE}"
                )

                if self.secrets:
                    await self.save_secrets()

        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

    async def save_secrets(self):
        try:
            secrets_dict = {}
            for secret_type, secret, url in self.secrets:
                if secret_type not in secrets_dict:
                    secrets_dict[secret_type] = []
                secrets_dict[secret_type].append((secret, url))

            with open(SECRETS_FILE, "w", encoding="utf-8") as f:
                for secret_type, secrets in sorted(secrets_dict.items()):
                    f.write(f"{secret_type}:\n")
                    for secret, url in sorted(secrets):
                        f.write(f"  - Secret: {secret}\n")
                        f.write(f"    Location: {url}\n")
                    f.write("\n")
        except Exception as e:
            logging.error(f"Error saving secrets to {SECRETS_FILE}: {e}")

    def is_valid_url(self, url, target_domain):
        parsed_url = urlparse(url)
        return parsed_url.hostname == target_domain

    def similar(self, a, b):
        return SequenceMatcher(None, a, b).ratio()


# Good Bye
if __name__ == "__main__":
    scanner = BugBountyHunter()
    asyncio.run(scanner.main())
