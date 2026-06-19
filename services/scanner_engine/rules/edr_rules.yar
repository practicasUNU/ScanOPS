/*
 * ScanOPS EDR — YARA Rules v1.0
 * Target: process command lines collected via `ps aux` / `ps -eo`
 * ENS Alto op.exp.4: detección de código dañino
 *
 * Severity meta values: CRITICAL / HIGH / MEDIUM / LOW
 * All rules should be non-overlapping with normal system administration.
 */


// ─── C2 Frameworks ────────────────────────────────────────────────────────────

rule C2_Curl_Suspicious_TLD {
    meta:
        description = "curl or wget POSTing data to suspicious free-TLD domains (common C2)"
        severity    = "HIGH"
        mitre       = "TA0011"
        family      = "C2_Framework"
    strings:
        $curl      = "curl" nocase fullword
        $wget      = "wget" nocase fullword
        $post1     = "-X POST" nocase
        $post2     = "--data" nocase
        $post3     = " -d "
        $tld_tk    = ".tk/"
        $tld_ga    = ".ga/"
        $tld_ml    = ".ml/"
        $tld_cf    = ".cf/"
        $tld_gq    = ".gq/"
        $tld_xyz   = ".xyz/"
        $tld_top   = ".top/"
        $tld_duckdns = "duckdns.org"
    condition:
        ($curl or $wget) and
        ($post1 or $post2 or $post3) and
        ($tld_tk or $tld_ga or $tld_ml or $tld_cf or $tld_gq or $tld_xyz or $tld_top or $tld_duckdns)
}

rule Cobalt_Strike_PowerShell_Beacon {
    meta:
        description = "Cobalt Strike Beacon via PowerShell encoded command patterns"
        severity    = "CRITICAL"
        mitre       = "TA0011"
        family      = "C2_Framework"
    strings:
        $ps_nop_enc  = "powershell -nop" nocase
        $ps_enc      = "-encodedCommand" nocase
        $ps_enc2     = "-enc " nocase
        $ps_hidden   = "-WindowStyle Hidden" nocase
        $ps_bypass   = "bypass" nocase
        $ps_noprofile = "-NoProfile" nocase
        $pipe_name1  = "msagent_"
        $pipe_name2  = "MSSE-"
        $pipe_name3  = "status_"
    condition:
        ($pipe_name1 or $pipe_name2 or $pipe_name3) or
        (($ps_nop_enc or $ps_noprofile) and $ps_bypass and ($ps_enc or $ps_enc2)) or
        ($ps_hidden and ($ps_enc or $ps_enc2) and $ps_bypass)
}

rule Metasploit_Framework_Patterns {
    meta:
        description = "Metasploit / Meterpreter tooling in process arguments"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "C2_Framework"
    strings:
        $msfp1  = "msfpayload" nocase
        $msfp2  = "msfvenom" nocase
        $msfp3  = "msfconsole" nocase
        $met1   = "meterpreter" nocase
        $multi  = "multi/handler" nocase
        $rev1   = "reverse_tcp" nocase
        $rev2   = "reverse_https" nocase
        $stager = "windows/shell" nocase
    condition:
        any of ($msfp1, $msfp2, $msfp3, $met1, $multi) or
        ($rev1 and $stager) or ($rev2 and $stager)
}

rule Empire_PowerShell_Agent {
    meta:
        description = "PowerShell Empire agent launcher pattern"
        severity    = "CRITICAL"
        mitre       = "TA0011"
        family      = "C2_Framework"
    strings:
        $iex1      = "IEX(" nocase
        $iex2      = "Invoke-Expression" nocase
        $dl1       = "DownloadString" nocase
        $dl2       = "WebClient" nocase
        $dl3       = "Net.WebClient" nocase
        $compress  = "IO.Compression" nocase
        $gzip      = "GzipStream" nocase
        $empire1   = "empire" nocase
        $empire2   = "stager" nocase
    condition:
        ($iex1 or $iex2) and ($dl1 or $dl2 or $dl3) or
        (($compress or $gzip) and ($iex1 or $iex2)) or
        ($empire1 and $empire2 and ($dl1 or $dl2))
}


// ─── Reverse Shells ───────────────────────────────────────────────────────────

rule Reverse_Shell_Bash_DevTCP {
    meta:
        description = "Bash reverse shell using /dev/tcp redirection"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "Reverse_Shell"
    strings:
        $devtcp  = "/dev/tcp/"
        $exec    = "exec " nocase
        $bash    = "bash" nocase
        $redir1  = ">&"
        $redir2  = "<>"
    condition:
        $devtcp and ($bash or $exec) and ($redir1 or $redir2)
}

rule Reverse_Shell_Netcat_Exec {
    meta:
        description = "Netcat reverse shell with -e or shell exec flag"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "Reverse_Shell"
    strings:
        $nc1  = " nc "
        $nc2  = "/nc "
        $ncat = "ncat "
        $flag_e  = " -e "
        $bin_sh  = "/bin/sh"
        $bin_bash = "/bin/bash"
        $flag_l  = " -l "
        $flag_lp = " -lp "
        $flag_lv = " -lv "
        $flag_ln = " -ln "
    condition:
        ($nc1 or $nc2 or $ncat) and
        ($flag_e and ($bin_sh or $bin_bash)) and
        ($flag_l or $flag_lp or $flag_lv or $flag_ln)
}

rule Reverse_Shell_Python_Socket {
    meta:
        description = "Python reverse shell via socket connect"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "Reverse_Shell"
    strings:
        $py    = "python" nocase
        $flag  = " -c "
        $sock  = "socket"
        $conn  = ".connect(" nocase
        $sh    = "subprocess" nocase
        $pty   = "pty" nocase
    condition:
        $py and $flag and $sock and ($conn or $sh or $pty)
}

rule Reverse_Shell_Perl {
    meta:
        description = "Perl reverse shell one-liner"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "Reverse_Shell"
    strings:
        $perl  = "perl" nocase fullword
        $flag  = " -e "
        $sock  = "socket" nocase
        $fork  = "fork" nocase
        $exec  = "exec " nocase
    condition:
        $perl and $flag and $sock and ($fork or $exec)
}

rule Reverse_Shell_PHP {
    meta:
        description = "PHP reverse shell via fsockopen"
        severity    = "CRITICAL"
        mitre       = "TA0002"
        family      = "Reverse_Shell"
    strings:
        $php    = "php" nocase fullword
        $flag   = " -r "
        $fsock  = "fsockopen" nocase
        $exec   = "exec(" nocase
        $shell  = "shell_exec" nocase
    condition:
        $php and $flag and $fsock and ($exec or $shell)
}


// ─── Data Exfiltration ────────────────────────────────────────────────────────

rule DataExfil_Socat_Relay {
    meta:
        description = "socat used to relay data or create tunnel (common exfil technique)"
        severity    = "HIGH"
        mitre       = "TA0010"
        family      = "DataExfiltration"
    strings:
        $socat  = "socat" nocase fullword
        $tcp    = "TCP:"
        $exec   = "EXEC:"
        $stdin  = "STDIN"
        $file   = "OPEN:"
        $pty    = "PTY"
    condition:
        $socat and ($tcp or $exec or $stdin or $file or $pty)
}

rule DataExfil_SCP_Sensitive_Files {
    meta:
        description = "SCP copying sensitive system files to remote host"
        severity    = "HIGH"
        mitre       = "TA0010"
        family      = "DataExfiltration"
    strings:
        $scp      = " scp " nocase
        $key      = " -i /"
        $shadow   = "/etc/shadow"
        $passwd   = "/etc/passwd"
        $ssh_keys = ".ssh/"
        $creds    = "credentials"
    condition:
        $scp and ($key or true) and ($shadow or $passwd or $ssh_keys or $creds)
}

rule DataExfil_Curl_ReadFile {
    meta:
        description = "curl reading sensitive local files and sending to remote"
        severity    = "HIGH"
        mitre       = "TA0010"
        family      = "DataExfiltration"
    strings:
        $curl     = "curl" nocase fullword
        $at_file  = " -d @/"
        $shadow   = "/etc/shadow"
        $passwd   = "/etc/passwd"
        $keys     = ".ssh/id_rsa"
        $env      = ".env"
        $post     = "-X POST" nocase
    condition:
        $curl and $post and ($at_file or $shadow or $passwd or $keys or $env)
}


// ─── Persistence ──────────────────────────────────────────────────────────────

rule Persistence_Cron_Injection {
    meta:
        description = "Cron job injection: writing a shell command into crontab or cron directory"
        severity    = "HIGH"
        mitre       = "TA0003"
        family      = "Persistence"
    strings:
        $crontab = "crontab" nocase
        $crond   = "/etc/cron" nocase
        $write1  = " >> "
        $write2  = " > "
        $cmd_dl  = "curl" nocase
        $cmd_bash = "/bin/bash"
        $cmd_nc  = " nc "
        $cmd_py  = "python" nocase
    condition:
        ($crontab or $crond) and
        ($write1 or $write2) and
        ($cmd_dl or $cmd_bash or $cmd_nc or $cmd_py)
}

rule Persistence_Systemd_Backdoor {
    meta:
        description = "Suspicious systemd unit creation with network or shell payloads"
        severity    = "HIGH"
        mitre       = "TA0003"
        family      = "Persistence"
    strings:
        $systemctl = "systemctl enable" nocase
        $unit_dir  = "systemd/system/"
        $exec_start = "ExecStart="
        $curl      = "curl" nocase
        $bash      = "/bin/bash"
        $nc        = " nc "
        $python    = "python" nocase
    condition:
        ($systemctl or $unit_dir or $exec_start) and
        ($curl or $bash or $nc or $python)
}

rule Persistence_Profile_Backdoor {
    meta:
        description = "Modifying shell startup files to install backdoor on login"
        severity    = "MEDIUM"
        mitre       = "TA0003"
        family      = "Persistence"
    strings:
        $bashrc  = ".bashrc"
        $profile = ".profile"
        $bash_pr = ".bash_profile"
        $zshrc   = ".zshrc"
        $write   = " >> "
        $curl    = "curl" nocase
        $nc      = " nc "
        $python  = "python" nocase
        $wget    = "wget" nocase
    condition:
        ($bashrc or $profile or $bash_pr or $zshrc) and
        $write and
        ($curl or $nc or $python or $wget)
}


// ─── Privilege Escalation ─────────────────────────────────────────────────────

rule PrivEsc_SUID_Exploitation {
    meta:
        description = "Searching for and executing SUID binaries (privilege escalation)"
        severity    = "MEDIUM"
        mitre       = "TA0004"
        family      = "PrivilegeEscalation"
    strings:
        $find     = "find " nocase
        $perm4000 = "-perm -4000"
        $perm_us  = "-perm /4000"
        $perm_u_s = "u+s"
        $exec_ls  = "-exec ls"
        $exec_sh  = "-exec sh"
        $exec_bash = "-exec bash"
    condition:
        $find and ($perm4000 or $perm_us or $perm_u_s) and
        ($exec_ls or $exec_sh or $exec_bash)
}

rule PrivEsc_Sudo_Shell_Spawn {
    meta:
        description = "sudo used to spawn a privileged shell (common post-exploitation)"
        severity    = "HIGH"
        mitre       = "TA0004"
        family      = "PrivilegeEscalation"
    strings:
        $sudo      = "sudo " nocase
        $bin_bash  = "/bin/bash"
        $bin_sh    = "/bin/sh"
        $bin_vi    = "/bin/vi"
        $bin_vim   = "/bin/vim"
        $bin_less  = "/bin/less"
        $bin_nano  = "/bin/nano"
        $nosudo    = "NOPASSWD"
        $sudoers   = "/etc/sudoers"
    condition:
        ($sudo and ($bin_bash or $bin_sh)) or
        ($sudo and ($bin_vi or $bin_vim or $bin_less or $bin_nano)) or
        $nosudo or
        $sudoers
}

rule PrivEsc_Sensitive_File_Read {
    meta:
        description = "Reading /etc/shadow or /etc/passwd then transmitting (credential theft)"
        severity    = "HIGH"
        mitre       = "TA0006"
        family      = "CredentialAccess"
    strings:
        $shadow  = "/etc/shadow"
        $passwd  = "/etc/passwd"
        $b64     = "base64"
        $nc      = " nc "
        $curl    = "curl" nocase
        $cat     = "cat " nocase
        $cp      = " cp " nocase
    condition:
        ($shadow or $passwd) and
        ($b64 or $nc or $curl or $cp)
}


// ─── Obfuscation ──────────────────────────────────────────────────────────────

rule Obfuscation_Base64_Pipe_Shell {
    meta:
        description = "Base64-decoded payload piped to shell (classic dropper technique)"
        severity    = "HIGH"
        mitre       = "TA0005"
        family      = "Obfuscation"
    strings:
        $b64d1   = "base64 -d" nocase
        $b64d2   = "base64 --decode" nocase
        $pipe_sh = "| sh"
        $pipe_ba = "| bash"
        $pipe_py = "| python" nocase
        $src1    = "echo " nocase
        $src2    = "printf " nocase
        $eval    = "eval " nocase
    condition:
        ($b64d1 or $b64d2) and
        ($pipe_sh or $pipe_ba or $pipe_py) and
        ($src1 or $src2 or $eval)
}

rule Obfuscation_OpenSSL_Decrypt_Exec {
    meta:
        description = "openssl decryption piped to shell (encrypted payload delivery)"
        severity    = "HIGH"
        mitre       = "TA0005"
        family      = "Obfuscation"
    strings:
        $ossl  = "openssl enc -d" nocase
        $pipe  = "| sh"
        $pipe2 = "| bash"
    condition:
        $ossl and ($pipe or $pipe2)
}

rule Obfuscation_PowerShell_EncodedCmd {
    meta:
        description = "PowerShell encoded command execution (obfuscated payload)"
        severity    = "HIGH"
        mitre       = "TA0005"
        family      = "Obfuscation"
    strings:
        $ps1  = "powershell" nocase
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $nop  = "-nop " nocase
        $bypass = "bypass" nocase
    condition:
        $ps1 and ($enc1 or $enc2) and ($nop or $bypass)
}


// ─── Lateral Movement ─────────────────────────────────────────────────────────

rule Lateral_SSH_StrictChecking_Disabled {
    meta:
        description = "SSH with host key checking disabled (automated lateral movement)"
        severity    = "HIGH"
        mitre       = "TA0008"
        family      = "LateralMovement"
    strings:
        $ssh      = " ssh " nocase
        $no_check = "StrictHostKeyChecking=no" nocase
        $dev_null = "UserKnownHostsFile=/dev/null" nocase
        $batch    = "BatchMode=yes" nocase
        $key      = " -i " nocase
    condition:
        $ssh and ($no_check or $dev_null or $batch) and $key
}
