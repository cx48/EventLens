const securityEvents = [
    {id: 4100, title: "PowerShell Engine Error", description: "An error occurred in the PowerShell engine. Could be due to script execution failures or policy restrictions.", severity: "medium"},
    {id: 4103, title: "PowerShell Module Logging", description: "Captures information about the loading and unloading of PowerShell modules. Useful for detecting unauthorized module usage.", severity: "medium"},
    {id: 4104, title: "PowerShell Script Block Logging", description: "Logs the execution of PowerShell script blocks. Contains the contents of the invoked commands.", severity: "high"},
    {id: 4624, title: "Successful Logon", description: "An account was successfully logged on. Remember to check Logon Type. For ex, Logon Type 10 indicates a Remote Interactive (RDP) logon.", severity: "medium"},
    {id: 4625, title: "Failed Logon", description: "An account failed to log on. Multiple failed attempts may indicate a brute-force attack.", severity: "high"},
    {id: 4634, title: "Account Logoff", description: "An account was logged off. Useful for tracking session durations.", severity: "low"},
    {id: 4648, title: "Logon with Explicit Credentials", description: "A logon was attempted using explicit credentials. May indicate credential theft or pass-the-hash attacks.", severity: "high"},
    {id: 4672, title: "Special Privileges Assigned", description: "Special privileges assigned to a new logon. Indicates administrative or system-level access.", severity: "high"},
    {id: 4688, title: "Process Creation", description: "A new process has been created. Monitoring this can help detect malicious activity.", severity: "medium"},
    {id: 4697, title: "Service Installation", description: "A service was installed on the system. Could be used by attackers to maintain persistence.", severity: "high"},
    {id: 4698, title: "Scheduled Task Created", description: "A scheduled task was created. May be used for persistence or delayed execution of malicious scripts.", severity: "medium"},
    {id: 4100, title: "PowerShell Engine Error", description: "An error occurred in the PowerShell engine. Could be due to script execution failures or policy restrictions.", severity: "medium"},
    {id: 4103, title: "PowerShell Module Logging", description: "Captures information about the loading and unloading of PowerShell modules. Useful for detecting unauthorized module usage.", severity: "medium"},
    {id: 4104, title: "PowerShell Script Block Logging", description: "Logs the execution of PowerShell script blocks. Contains the contents of the invoked commands.", severity: "high"},
    {id: 4702, title: "Scheduled Task Updated", description: "A scheduled task was updated. Monitoring changes can help detect tampering.", severity: "medium"},
    {id: 4719, title: "System Audit Policy Changed", description: "System audit policy was changed. Could be an attempt to cover tracks.", severity: "high"},
    {id: 4720, title: "User Account Created", description: "A user account was created. May indicate unauthorized account creation.", severity: "high"},
    {id: 4722, title: "User Account Enabled", description: "A user account was enabled. Could be used to reactivate dormant accounts.", severity: "medium"},
    {id: 4724, title: "Password Reset Attempt", description: "An attempt was made to reset an account's password. May indicate unauthorized access attempts.", severity: "medium"},
    {id: 4725, title: "User Account Disabled", description: "A user account was disabled. Could indicate administrative action or threat mitigation.", severity: "medium"},
    {id: 4726, title: "User Account Deleted", description: "A user account was deleted. Could be an attempt to remove evidence.", severity: "high"},
    {id: 4728, title: "Member Added to Security-Enabled Global Group", description: "A member was added to a security-enabled global group. May indicate privilege escalation.", severity: "high"},
    {id: 4732, title: "Member Added to Security-Enabled Local Group", description: "A member was added to a security-enabled local group. Could be used to gain unauthorized access.", severity: "high"},
    {id: 4738, title: "User Account Changed", description: "A user account was changed. Monitoring changes can help detect unauthorized modifications.", severity: "medium"},
    {id: 4741, title: "Computer Account Created", description: "A computer account was created. May indicate the addition of unauthorized devices.", severity: "high"},
    {id: 4742, title: "Computer Account Changed", description: "A computer account was changed. Could be used to alter system configurations.", severity: "medium"},
    {id: 4767, title: "User Account Unlocked", description: "A user account was unlocked. May indicate attempts to regain access.", severity: "medium"},
    {id: 4768, title: "Kerberos TGT Request", description: "A Kerberos authentication ticket (TGT) was requested. First step in Kerberos login.", severity: "medium"},
    {id: 4769, title: "Kerberos Service Ticket Request", description: "A Kerberos service ticket was requested. Indicates access to specific resources.", severity: "medium"},
    {id: 4770, title: "Kerberos TGT Renewal", description: "A Kerberos TGT was renewed. Indicates extended sessions or reuse.", severity: "low"},
    {id: 4771, title: "Kerberos Pre-Authentication Failed", description: "Kerberos pre-authentication failed. May indicate brute-force attempts.", severity: "high"},
    {id: 4776, title: "NTLM (DC) Authentication Attempt", description: "The domain controller attempted to validate credentials via NTLM. Often used in legacy systems.", severity: "medium"},
    {id: 4781, title: "Account Name Changed", description: "The name of an account was changed. Could be used to obfuscate malicious activity.", severity: "medium"},
    {id: 4798, title: "User's Local Group Membership Enumerated", description: "A user's local group membership was enumerated. May indicate reconnaissance activity.", severity: "medium"},
    {id: 5140, title: "Network Share Accessed", description: "A network share object was accessed. Monitoring can help detect unauthorized data access.", severity: "low"},
    {id: 5145, title: "Network Share Object Checked", description: "A network share object was checked to see whether the client can be granted desired access. Useful for detecting access attempts.", severity: "low"},
    {id: 5156, title: "Windows Filtering Platform Connection Allowed", description: "The Windows Filtering Platform has permitted a connection. Monitoring can help detect unexpected network activity.", severity: "low"},
    {id: 5158, title: "Windows Filtering Platform Blocked", description: "The Windows Filtering Platform has blocked a connection. Could indicate attempted unauthorized access.", severity: "high"},
    {id: 5376, title: "Credential Manager Credentials Accessed", description: "Credential Manager credentials were accessed. May indicate credential theft.", severity: "high"},
    {id: 5377, title: "Credential Manager Credentials Backed Up", description: "Credential Manager credentials were backed up. Could be used to exfiltrate credentials.", severity: "high"},
    {id: 5378, title: "Credential Manager Credentials Restored", description: "Credential Manager credentials were restored from a backup. May indicate unauthorized credential usage.", severity: "high"},
    {id: 4778, title: "Session Reconnected", description: "A session was reconnected to a Window Station. Useful for tracking RDP session", severity: "medium"},
    {id: 7045, title: "New Service Installed", description: "A new service was installed on the system. Indicates possible persistence or system changes.", severity: "medium"},
]
   
  

// Sysmon Events
const sysmonEvents = [
    {
        id: 1,
        title: "Process Creation",
        description: "Fires when a process starts, capturing details like command line, and user.",
        severity: "medium"
    },
    {
        id: 2,
        title: "File Creation Time Changed",
        description: "Logs when a process alters a file’s creation time, often used to hide malicious activity.",
        severity: "high"
    },
    {
        id: 3,
        title: "Network Connection",
        description: "Indicates a detected network connection (inbound or outbound).",
        severity: "low"
    },
    {
        id: 4,
        title: "Sysmon Service State Changed",
        description: "Generated when the Sysmon service starts, stops, or undergoes a state change.",
        severity: "medium"
    },
    {
        id: 5,
        title: "Process Terminated",
        description: "Records when a process completes or is forcibly terminated.",
        severity: "low"
    },
    {
        id: 6,
        title: "Driver Loaded",
        description: "Monitors the loading of kernel-mode drivers, which can reveal unauthorized or suspicious drivers.",
        severity: "high"
    },
    {
        id: 7,
        title: "Image Loaded",
        description: "Fires when a module (DLL or similar) is loaded into a process, capturing load-time details.",
        severity: "medium"
    },
    {
        id: 8,
        title: "CreateRemoteThread",
        description: "Occurs when CreateRemoteThread is used to inject or manipulate a remote process.",
        severity: "high"
    },
    {
        id: 9,
        title: "RawAccessRead",
        description: "Indicates direct disk or volume read operations, bypassing normal file system APIs.",
        severity: "high"
    },
    {
        id: 10,
        title: "Process Access",
        description: "Triggered when one process opens or attempts to manipulate another process (e.g., suspicious memory reads, DLL Injection, etc).",
        severity: "high"
    },
    {
        id: 11,
        title: "File Created",
        description: "Logs creation of new files, capturing metadata such as path and process.",
        severity: "medium"
    },
    {
        id: 12,
        title: "Registry Object Added/Deleted",
        description: "Fires when registry keys or values are newly created or removed.",
        severity: "medium"
    },
    {
        id: 13,
        title: "Registry Value Set",
        description: "Records modifications to registry values, often used in persistence or configuration changes.",
        severity: "medium"
    },
    {
        id: 14,
        title: "Registry Key Renamed",
        description: "Captures when an existing registry key is renamed, which may indicate stealthy changes.",
        severity: "medium"
    },
    {
        id: 15,
        title: "FileCreateStreamHash",
        description: "Detects creation of alternate data streams (ADS), logging stream content hashes.",
        severity: "high"
    },
    {
        id: 16,
        title: "Sysmon Config Change",
        description: "Occurs when the Sysmon configuration is updated or replaced, possibly altering monitoring rules.",
        severity: "high"
    },
    {
        id: 17,
        title: "Pipe Created",
        description: "Logs the creation of named pipes, which can facilitate interprocess communication or lateral movement.",
        severity: "medium"
    },
    {
        id: 18,
        title: "Pipe Connected",
        description: "Indicates a process connected to an existing named pipe, potentially for data transfer or commands.",
        severity: "medium"
    },
    {
        id: 19,
        title: "WmiEventFilter",
        description: "A WMI event filter was created, often used by attackers for persistent or automated tasks.",
        severity: "high"
    },
    {
        id: 20,
        title: "WmiEventConsumer",
        description: "Logs creation of a WMI event consumer, a powerful method for scheduled or persistent actions.",
        severity: "high"
    },
    {
        id: 21,
        title: "WmiEventConsumerToFilter",
        description: "A WMI consumer was bound to a filter, finalizing an automated WMI event subscription.",
        severity: "high"
    },
    {
        id: 22,
        title: "DNS Query",
        description: "Captures DNS queries, including requested domains and process details.",
        severity: "low"
    },
    {
        id: 23,
        title: "File Delete",
        description: "Records file deletion attempts, logging file names and associated processes.",
        severity: "medium"
    },
    {
        id: 24,
        title: "Clipboard Change",
        description: "Detects changes to the system clipboard, which can indicate data exfiltration or script-based attacks.",
        severity: "medium"
    },
    {
        id: 25,
        title: "Process Tampering",
        description: "Indicates in-memory modifications or tampering with process structures (e.g., code injection).",
        severity: "high"
    },
    {
        id: 26,
        title: "File Delete Detected",
        description: "Logs the removal of files, capturing pre-deletion attributes or hashes for forensic analysis.",
        severity: "medium"
    }
];


//System Events
const systemEvents = [
                  {
                      id: 21,
                      title: "RDS Session Logon Succeeded",
                      description: "Remote Desktop Services session logon was successful.",
                      severity: "medium"
                  },
                  {
                      id: 22,
                      title: "RDS Shell Start Notification",
                      description: "Remote Desktop Services received a shell start notification.",
                      severity: "low"
                  },
                  {
                      id: 23,
                      title: "RDS Session Logoff Succeeded",
                      description: "Remote Desktop Services session logoff completed successfully.",
                      severity: "medium"
                  },
                  {
                      id: 24,
                      title: "RDS Session Disconnected",
                      description: "Remote Desktop Services session was disconnected.",
                      severity: "low"
                  },
                  {
                      id: 25,
                      title: "RDS Session Reconnected",
                      description: "Remote Desktop Services session reconnected successfully.",
                      severity: "medium"
                  },

                  // 100, 102: Task Scheduler
                  {
                      id: 100,
                      title: "Task Scheduler Started Task",
                      description: "Task Scheduler started an instance of a task for a user.",
                      severity: "low"
                  },
                  {
                      id: 102,
                      title: "Task Scheduler Finished Task",
                      description: "Task Scheduler completed an instance of a task for a user.",
                      severity: "low"
                  },

                  // 104: System Event Log Cleared
                  {
                      id: 104,
                      title: "Event Log Cleared",
                      description: "A Windows event log (System, Application, etc.) was cleared.",
                      severity: "high"
                  },

                  // 106, 141: Task Scheduler
                  {
                      id: 106,
                      title: "New Scheduled Task Registered",
                      description: "A user registered a new task with Task Scheduler.",
                      severity: "medium"
                  },
                  {
                      id: 141,
                      title: "Scheduled Task Deleted",
                      description: "A user deleted a Task Scheduler task.",
                      severity: "medium"
                  },

                  // 216, 325, 326, 327: ESENT (Application)
                  {
                      id: 216,
                      title: "ESENT Database Location Changed",
                      description: "A database location change was detected by the ESENT engine.",
                      severity: "low"
                  },
                  {
                      id: 325,
                      title: "ESENT Database Created",
                      description: "The ESENT database engine created a new database.",
                      severity: "low"
                  },
                  {
                      id: 326,
                      title: "ESENT Database Attached",
                      description: "The ESENT database engine attached a database.",
                      severity: "low"
                  },
                  {
                      id: 327,
                      title: "ESENT Database Detached",
                      description: "The ESENT database engine detached a database.",
                      severity: "low"
                  },

                  // 400: PowerShell 
                  {
                      id: 400,
                      title: "PowerShell Engine State Changed",
                      description: "The PowerShell engine changed state (e.g., from None to Available).",
                      severity: "low"
                  },
                  {
                      id: 401,
                      title: "Service Failed to Start",
                      description: "A service failed to start.",
                      severity: "medium"
                  },

                  // 600: PowerShell
                  {
                      id: 600,
                      title: "PowerShell Provider Started",
                      description: "A PowerShell provider was started.",
                      severity: "low"
                  },

                  // 601 (original entry, kept)
                  {
                      id: 601,
                      title: "Driver Failed to Load",
                      description: "A driver failed to load.",
                      severity: "high"
                  },
                  {
                      id: 800, 
                      title: "Remote PowerShell Session Established",
                      description: "Indicates the establishment of a remote PowerShell session. Could be used for remote administration or attacks.",
                      severity: "high"
                  },
                  // 7009: System
                  {
                      id: 7009,
                      title: "Service Startup Timeout",
                      description: "A service did not respond within the expected timeout period.",
                      severity: "medium"
                  },

                  // 7034: System
                  {
                      id: 7034,
                      title: "Service Terminated Unexpectedly",
                      description: "A service ended unexpectedly and may repeat if the issue persists.",
                      severity: "medium"
                  },

                  // 7045: System
                  {
                      id: 7045,
                      title: "New Service Installed",
                      description: "A new service was installed on the system.",
                      severity: "medium"
                  },

                  // 1000: Application
                  {
                      id: 1000,
                      title: "Application Error",
                      description: "An application encountered a crash or fault.",
                      severity: "low"
                  },
                  {
                      id: 1002,
                      title: "Application Hang",
                      description: "An application became unresponsive (hang).",
                      severity: "medium"
                  },

                  // 1100 (original entry, kept)
                  {
                      id: 1100,
                      title: "Event Log Service Shutdown",
                      description: "The Event Log service was shut down.",
                      severity: "high"
                  },

                  // 1102: Security Audit Log Cleared 
                  {
                      id: 1102,
                      title: "Security Audit Log Cleared",
                      description: "The Security audit log was cleared, possibly indicating tampering.",
                      severity: "high"
                  },

                  // 1104
                  {
                      id: 1104,
                      title: "Security Log Full",
                      description: "The Security event log is full.",
                      severity: "medium"
                  },
                  {
                      id: 1105,
                      title: "Event Log Backup Failed",
                      description: "Event log automatic backup failed.",
                      severity: "medium"
                  },
                  {
                      id: 1108,
                      title: "Event Logging Error",
                      description: "The event logging service encountered an error.",
                      severity: "medium"
                  },

                  // 1116, 1117: Windows Defender
                  {
                      id: 1116,
                      title: "Defender Malware Detected",
                      description: "Microsoft Defender detected malware or potentially unwanted software.",
                      severity: "high"
                  },
                  {
                      id: 1117,
                      title: "Defender Action Performed",
                      description: "Microsoft Defender took action to protect the system from malware.",
                      severity: "high"
                  },

                  // 1149: Terminal Services (RemoteConnectionManager)
                  {
                      id: 1149,
                      title: "RDS Network Authentication Succeeded",
                      description: "Remote Desktop Services user successfully authenticated over the network.",
                      severity: "medium"
                  },

                  // 2000
                  {
                      id: 2000,
                      title: "Application Crash",
                      description: "An application crashed.",
                      severity: "low"
                  },

                  // 261: Terminal Services (RemoteConnectionManager)
                  {
                      id: 261,
                      title: "RDS Listener Received Connection",
                      description: "A Remote Desktop Services listener (RDP-Tcp) received a connection attempt.",
                      severity: "medium"
                  },

                  // 4104: PowerShell/Operational
                  {
                      id: 4104,
                      title: "PowerShell ScriptBlock Logging",
                      description: "ScriptBlock logging triggered for created or executed scripts.",
                      severity: "medium"
                  }
                  ];


// Logon Types
const logonTypeCodes = [
    {
      type: 2,
      description: "Interactive (Console): A user logged on directly at the machine’s console"
    },
    {
      type: 3,
      description: "Network: Common for SMB, IKE, or network-based logons. With NLA for RDP, the initial handshake may register as Type 3"
    },
    {
      type: 4,
      description: "Batch: Used by scheduled tasks or batch jobs that run without direct user interaction"
    },
    {
      type: 5,
      description: "Service: Windows service logons (e.g., start under a service account)"
    },
    {
      type: 7,
      description: "Unlock: A user unlocking a workstation session (e.g., after screen lock)"
    },
    {
      type: 8,
      description: "Network Cleartext: Network logon sending credentials in plaintext (rare/legacy)"
    },
    {
      type: 9,
      description: "New Credentials (RunAs): A new set of credentials specified from an existing session"
    },
    {
      type: 10,
      description: "Remote Interactive: Typically RDP sessions. With NLA, the final stage is recognized as Type 10"
    },
    {
      type: 11,
      description: "Cached Interactive: Uses locally cached credentials (e.g., offline domain login)"
    },
    {
      type: 12,
      description: "Cached Remote Interactive: Similar to Type 10, but uses cached credentials (offline RDP)"
    },
    {
      type: 13,
      description: "Cached Unlock: Similar to Type 7, but relies on locally cached credentials (offline unlock)"
    }
  ];
  

// Event Providers
const eventProviders = [
  { 
      name: "Microsoft-Windows-Security-Auditing", 
      description: "Primary provider for security audit events (Account Logon, Logon/Logoff, Object Access, etc.)",
      exampleEvents: "4624, 4625, 4648, 4663, 4672, 4688, 4697, 4702, 4719, 4720, 4728, 4732, 4741, 4767, 4776, 5140, 5156"
  },
  { 
      name: "Microsoft-Windows-Sysmon", 
      description: "System Monitor provides detailed logging about process creation, network connections, and other system activities",
      exampleEvents: "1 (Process creation), 3 (Network connection), 7 (Image loaded), 8 (CreateRemoteThread), 10 (Process access)"
  },
  { 
      name: "Microsoft-Windows-PowerShell", 
      description: "Logs PowerShell engine events and operational activities",
      exampleEvents: "400 (Engine state), 4103 (Module logging), 4104 (Script block logging)"
  },
  { 
      name: "Microsoft-Windows-TaskScheduler", 
      description: "Records scheduled task creation, modification, and execution",
      exampleEvents: "106 (Task registered), 141 (Task deleted), 100 (Task started)"
  },
  { 
      name: "Microsoft-Windows-TerminalServices-LocalSessionManager", 
      description: "Logs Remote Desktop Services session activities",
      exampleEvents: "21 (Session logon), 23 (Session logoff), 24 (Session disconnected)"
  },
  { 
      name: "Microsoft-Windows-Windows Defender", 
      description: "Records malware detection and protection events",
      exampleEvents: "1116 (Malware detected), 1117 (Action taken)"
  },
  { 
      name: "Microsoft-Windows-DNS-Client", 
      description: "Logs DNS query resolution events",
      exampleEvents: "3008 (DNS query response), 3020 (DNS query failure)"
  },
  { 
      name: "Microsoft-Windows-Bits-Client", 
      description: "Background Intelligent Transfer Service (BITS) events",
      exampleEvents: "3 (Transfer started), 4 (Transfer completed)"
  }
];