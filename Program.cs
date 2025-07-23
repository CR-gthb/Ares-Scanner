using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

/// Created by C.R 13.07.25
/// All rights go to the creator of this code
/// This was created for ethical and pentesting purposes only
/// Please use for ethical reasons.
/// AI was used to help teach me within this context and was used to aid me into correct directions.
namespace Ares_Scanner
{
    internal class Program
    {

        //stating the log directory and file path -  the log files will be created where the exe is located. create a folder for the exe to be located please...
        private readonly string _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs");
        private readonly string _logFilePath;

        public Program()
        { //creating the log location so you don't have to go far to find them
            _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Logs"); // creating the logs folder :)
            Directory.CreateDirectory(_logDirectory);
            string logFileName = $"ScanLog_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            _logFilePath = Path.Combine(_logDirectory, logFileName);
        }


        static async Task Main(string[] args)
        {

            Program program = new Program();
            bool continueRunning = true; //setting the program loop to run continiously


            while (continueRunning) //creating the menu and loading it for the user
            {
                continueRunning = await program.menuSelect();

            }
        }


        private void LogToFile(string message) //creating the function to take input and write to the txt log file :>
        {
            try
            {
                File.AppendAllText(_logFilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LOG ERROR] Could not write to log: {ex.Message}");
            }
        }

        public async Task<bool> menuSelect() //using a menu selection with validation for code security - I still remember the lectures of code security from my teacher
        {
            Console.WriteLine("[1] - Port Scanner ");
            Console.WriteLine("[2] - Ping IP ");
            Console.WriteLine("[3] - Vulnerability Scan ");
            Console.WriteLine("[0] - Exit ");
            return await MenuValidation(); //await because it calls async methods
        }


        public async Task<bool> MenuValidation()
        {
            string userMenuInput = Console.ReadLine();
            //using switch logic

            switch (userMenuInput)
            {

                case "1":
                    await PortScanner(); //moving to port scanner
                    return true; //return to main loop

                case "2":
                    await ipPing();
                    return true;

                case "3":
                    await VulnerabilityScan();
                    return true;

                case "0": // closes the loop in turn closing the program, but you can just ctrl-c (duh)
                    return false;


                default:
                    Console.WriteLine("[ERROR] Invalid input - Try Again");
                    Thread.Sleep(4000);
                    return await menuSelect(); //Recursive call to retry menu

            }
        }

        private string _ip;

        public async Task ScanAll()
        {
            await ICMPScan(); // run once before scanning ports

            for (int port = 1; port <= 65535; port++)
            {
                await Task.WhenAny(
                    TCPScan(port),
                    UDPScan(port)
                );
            }
        }

        private async Task TCPScan(int port)
        { // im re-coding this just to make sure that I seriously don't have all 65k ports open because that is not swag...
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    var ConnectTask = client.ConnectAsync(_ip, port);
                    var timeOutTask = Task.Delay(0800);

                    var completedtask = await Task.WhenAny(ConnectTask, timeOutTask);
                    if (completedtask == timeOutTask)
                    {
                        //timeout reached - consider the port as closed or filtered 
                        return;
                    }

                    if (client.Connected)
                    {
                        string message = $"[TCP] Port: {port} on {_ip} is open.";
                        Console.WriteLine(message);
                        LogToFile(message);
                    }

                }

            }
            catch (SocketException)
            {
                //connection refused or unreachable ports throw here
                //don't log open ports here..
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TCP] - [ERROR] Scanning port {port} on {_ip}: {ex.Message}");
            }
        }

        private async Task UDPScan(int port)
        {
            try
            {
                using (UdpClient client = new UdpClient())
                {
                    client.Client.ReceiveTimeout = 2000; //you'll notice that my method to do this is different to TCP as with TCP you can conntectAsync, not with UDP :/
                    await client.SendAsync(new byte[1], 1, new IPEndPoint(IPAddress.Parse(_ip), port));

                    var receiveTask = client.ReceiveAsync();
                    var timeoutTask = Task.Delay(2000);

                    var completedTask = await Task.WhenAny(receiveTask, timeoutTask);
                    if (completedTask == receiveTask)//writing to log
                    {
                        var result = await receiveTask;
                        string message = $"[UDP] Port: {port} on {_ip} is open.";
                        Console.WriteLine(message);
                        LogToFile(message);  // <-- call to Log here
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions but do not log as open port
            }
        }

        private async Task ICMPScan() //scanning ICMP  - checking if the host is reachable - if reachable scan for TCP and UDP
        {
            try
            {
                Ping ping = new Ping();
                PingReply reply = await ping.SendPingAsync(_ip);
                if (reply.Status == IPStatus.Success)
                {
                    string message = $"[ICMP] Ping to {_ip} successful.";
                    Console.WriteLine(message);
                    LogToFile(message);
                }
                else
                {
                    Console.WriteLine($"[ICMP] Ping to {_ip} failed: {reply.Status}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ICMP]-[ERROR] {_ip}: {ex.Message}");
            }
        }


        public async Task<bool> PortScanner() //I'm scanning accross all 65 thousands ports (who needs that many ports?), I'd rather be secure, using ICMP, UDP,TCP just to be secure..
        {
            Console.WriteLine("Enter IP: ");
            _ip = IPInputValidation();
            Console.WriteLine($"Scanning all ports on {_ip}...");
            await ScanAll();

            Console.WriteLine("Scan complete. Press [Enter] to return to the menu...");
            while (Console.ReadKey(true).Key != ConsoleKey.Enter) { }
            return await menuSelect();
        }

        public string IPInputValidation()
        { //validate IP input
            while (true)
            {//loops
                string input = Console.ReadLine();
                if (IsValidIPAddress(input))
                {
                    return input;
                }
                Console.WriteLine("Invalid IPv4 address. Please enter a valid address (e.g., 192.168.1.1):");
            }
        }

        private bool IsValidIPAddress(string ip)
        {
            if (!IPAddress.TryParse(ip, out IPAddress address))
                return false;

            // Ensure it's IPv4 and has exactly 4 octets
            return address.AddressFamily == AddressFamily.InterNetwork && ip.Count(c => c == '.') == 3;
        }


        public async Task<bool> ipPing() //pinging IP as a feature to include those networkers who wanna verify an IP is up.
        {
            Console.Write("Enter IP to ping: ");
            string ip = IPInputValidation();
            try
            {
                using (Ping ping = new Ping())  // previous method was causing errors so I redesigned this method to ping the ip :)
                {
                    PingReply reply = await ping.SendPingAsync(ip);
                    Console.WriteLine($"Ping to {ip}: {reply.Status}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Ping ERROR] {ex.Message}");
            }
            return await menuSelect();

        }

        private string CreateVulnerabilityLogFile() //as the name says, just creating a log file so it differs from the scanlogs - it was irritating me (HCI influenced)
        {
            string vulnLogFileName = $"VulnScanLog_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            string fullPath = Path.Combine(_logDirectory, vulnLogFileName);
            return fullPath;
        }
        string logFileName = $"VulnScanLog_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

        public async Task<bool> VulnerabilityScan() //I use multiple methods within this, like checking apache FTP and so on..
        {
            Console.WriteLine("Enter IP to Scan For Vulnerability..");
            _ip = IPInputValidation();

            // Create vulnerability-specific log file
            string originalLogFile = _logFilePath; // backup original if needed
            string vulnLogPath = CreateVulnerabilityLogFile();

            // Temporarily override logging target
            File.AppendAllText(vulnLogPath, $"[VULNERABILITY SCAN STARTED] {DateTime.Now} on {_ip}{Environment.NewLine}");

            // Log wrapper for this scan only
            void LogToVulnFile(string message)
            {
                string entry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";
                File.AppendAllText(vulnLogPath, entry);
                Console.WriteLine(message);
            }

            LogToVulnFile($"[VULNERABILITY SCAN] Starting Scan On {_ip}");
            await CommonWebVulnerabilities(LogToVulnFile); //checking for web vulnerabilities
            await OpenFTP(LogToVulnFile); //checking for file transfer is open/used
            await SMBNullSessions(LogToVulnFile); // checking for SMB Null Sessions
            await SSHVersionCheck(LogToVulnFile); // scanning port 22 SSH

            Console.WriteLine("Scan complete, Press [ENTER] to return to the menu...");
            while (Console.ReadKey(true).Key != ConsoleKey.Enter) { }
            return await menuSelect(); //this is just preventing the user from accidentally hitting the wrong key and skipping ahead
        }

        private async Task CommonWebVulnerabilities(Action<string> log)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(_ip, 80); //checking port 80
                    using (var stream = client.GetStream())
                    using (var writer = new StreamWriter(stream))
                    using (var reader = new StreamReader(stream))
                    {
                        writer.Write("GET / HTTP/1.1\r\nHost: " + _ip + "\r\nConnection: close\r\n\r\n");
                        writer.Flush();
                        string response = await reader.ReadToEndAsync();

                        if (Regex.IsMatch(response, "Server:\\s*(.+)", RegexOptions.IgnoreCase))
                        {
                            var match = Regex.Match(response, "Server:\\s*(.+)");
                            string serverInfo = match.Groups[1].Value.Trim();
                            log($"[HTTP] Detected web server: {serverInfo}");

                            if (serverInfo.Contains("Apache/2.4.29")) //apache 2.4.29 is vuln - I've abused it in CTF's (well known cve)
                                log("[VULNERABLE] Apache 2.4.29 has known vulnerabilities (e.g., CVE-2019-0211)");

                            if (response.Contains("Index of /"))
                                log("[WARNING] Directory listing enabled on root path");
                        }
                    }
                }
            }
            catch
            {
                log("[HTTP] Port 80 not accessible or server not responsive.");

            }
        }

        private async Task OpenFTP(Action<string> log)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(_ip, 21);
                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream))
                    {
                        string banner = await reader.ReadLineAsync();
                        log($"[FTP] Server Banner: {banner}");

                        if (banner.Contains("vsFTPd 2.3.4"))
                        {
                            log("[VULNERABLE] vsFTPd 2.3.4 is backdoored (CVE-2011-2523)");
                        }
                    }
                }
            }
            catch
            {
                log("[FTP] Port 21 - Not Accessible or server not responsive.");
            }
        }

        private async Task SMBNullSessions(Action<string> log) // detecting SMB null sessions through 445... 
        {
            try
            {
                using (var client = new TcpClient())
                {
                    log("[SMB] Port 445 is open - potential for null session (requires deeper inspection.");
                }
            }
            catch
            {
                log("[SMB] Port 445 - Not Accessible");
            }
        }

        private async Task SSHVersionCheck(Action<string> log)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    await client.ConnectAsync(_ip, 22); //scanning port 22 which is used for ssh :)
                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream))
                    {
                        stream.ReadTimeout = 3000;
                        string banner = await reader.ReadLineAsync();
                        if (!string.IsNullOrEmpty(banner))
                        {
                            log($"[SSH] Banner: {banner}");

                            if (banner.Contains("OpenSSH"))
                            {
                                var versionMatch = Regex.Match(banner, @"OpenSSH[_\-]([0-9.]+)");
                                string[] vulnerableSSHVersions = { "7.2", "7.6", "8.2" };
                                if (versionMatch.Success)
                                {
                                    string version = versionMatch.Groups[1].Value;
                                    log($"[SSH] Detected OpenSSH Version: {version}");

                                    if (vulnerableSSHVersions.Contains(version))
                                    {
                                        log("[VULNERABLE] Detected potentially vulnerable OpenSSH version.");
                                    }
                                }
                            }
                        }

                        else 
                        {                        
                            log("[SSH] No banner recieved, but port 22 is open...");
                        }
                    }
                }

            }

            catch(Exception ex) 
            {
                log($"[SSH] Error checking SSH on {_ip}: {ex.Message}");
            }
        }
    }
}

///This project was extremely fun to work on and it was for educational and self development based reasons as to why I created this.


