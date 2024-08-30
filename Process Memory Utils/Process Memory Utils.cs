using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Memory
{
    public class Mem : IDisposable
    {
        // Constants for memory access
        private const uint PROCESS_ALL_ACCESS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
        private const int PROCESS_CREATE_THREAD = 0x0002;
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_OPERATION = 0x0008;
        private const int PROCESS_VM_WRITE = 0x0020;
        private const int PROCESS_VM_READ = 0x0010;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_READWRITE = 0x04;

        // Handle for the target process
        public IntPtr ProcessHandle { get; private set; } = IntPtr.Zero;
        public Process TargetProcess { get; private set; }
        public Dictionary<string, IntPtr> Modules { get; private set; } = new();
        private ProcessModule MainModule;

        #region P/Invoke Declarations
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetPrivateProfileString(string lpAppName, string lpKeyName, string lpDefault, StringBuilder lpReturnedString, uint nSize, string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
        #endregion

        // Open a process given its ID
        public bool OpenGameProcess(int processId)
        {
            if (processId == 0) return false;

            try
            {
                TargetProcess = Process.GetProcessById(processId);
                if (TargetProcess?.Responding != true) return false;

                ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                if (ProcessHandle == IntPtr.Zero) throw new InvalidOperationException("Failed to open process.");

                MainModule = TargetProcess.MainModule;
                LoadModules();
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error opening process: {ex.Message}");
                return false;
            }
        }

        // Load all modules for the current process
        private void LoadModules()
        {
            Modules.Clear();
            foreach (ProcessModule module in TargetProcess.Modules)
            {
                if (!string.IsNullOrEmpty(module.ModuleName) && !Modules.ContainsKey(module.ModuleName))
                {
                    Modules[module.ModuleName] = module.BaseAddress;
                }
            }
        }

        // Get the process ID from its name
        public static int GetProcessIdByName(string name)
        {
            return Process.GetProcessesByName(name).FirstOrDefault()?.Id ?? 0;
        }

        // Load a code or configuration from a file
        public string LoadCode(string name, string file)
        {
            StringBuilder result = new(1024);
            if (!string.IsNullOrEmpty(file))
            {
                GetPrivateProfileString("codes", name, "", result, (uint)result.Capacity, file);
            }
            else
            {
                result.Append(name);
            }
            return result.ToString();
        }

        // Load an address from a code
        private UIntPtr LoadUIntPtrCode(string name, string path = "")
        {
            string code = LoadCode(name, path);
            string offsetString = code.Split('+').LastOrDefault();

            if (string.IsNullOrEmpty(offsetString))
                return UIntPtr.Zero;

            int offset = Convert.ToInt32(offsetString, 16);

            if (code.Contains("base") || code.Contains("main"))
                return (UIntPtr)((long)MainModule.BaseAddress + offset);

            string[] parts = code.Split('+');
            if (Modules.TryGetValue(parts[0], out IntPtr moduleBase))
                return (UIntPtr)((long)moduleBase + offset);

            return (UIntPtr)offset;
        }

        // Read a string from the target process memory
        public string ReadString(string code, string file = "")
        {
            UIntPtr baseAddress = LoadUIntPtrCode(code, file);
            byte[] buffer = new byte[10];

            if (ReadProcessMemory(ProcessHandle, baseAddress, buffer, (UIntPtr)buffer.Length, out _))
                return Encoding.UTF8.GetString(buffer).TrimEnd('\0');

            return string.Empty;
        }

        // Write to the target process memory
        public bool WriteMemory(string code, string type, string value, string file = "")
        {
            UIntPtr baseAddress = LoadUIntPtrCode(code, file);
            byte[] buffer = type.ToLower() switch
            {
                "float" => BitConverter.GetBytes(float.Parse(value)),
                "int" => BitConverter.GetBytes(int.Parse(value)),
                "byte" => new[] { byte.Parse(value) },
                "string" => Encoding.UTF8.GetBytes(value),
                _ => throw new ArgumentException("Invalid type specified."),
            };

            return WriteProcessMemory(ProcessHandle, baseAddress, buffer, (uint)buffer.Length, out _);
        }

        // Resolve complex memory addresses
        private UIntPtr GetCodeAddress(string name, string path, int size = 4)
        {
            string code = LoadCode(name, path);
            if (string.IsNullOrEmpty(code)) return UIntPtr.Zero;

            string[] offsets = code.Split(new[] { '+', ',' }, StringSplitOptions.RemoveEmptyEntries);
            uint address = Convert.ToUInt32(offsets[0], 16);
            byte[] buffer = new byte[size];

            if (code.Contains("base") || code.Contains("main"))
            {
                ReadProcessMemory(ProcessHandle, (UIntPtr)((long)MainModule.BaseAddress + address), buffer, (UIntPtr)size, out _);
            }
            else if (Modules.TryGetValue(offsets[0], out IntPtr moduleBase))
            {
                ReadProcessMemory(ProcessHandle, (UIntPtr)((long)moduleBase + address), buffer, (UIntPtr)size, out _);
            }

            for (int i = 1; i < offsets.Length; i++)
            {
                address = BitConverter.ToUInt32(buffer, 0) + Convert.ToUInt32(offsets[i], 16);
                ReadProcessMemory(ProcessHandle, (UIntPtr)address, buffer, (UIntPtr)size, out _);
            }

            return (UIntPtr)address;
        }

        // Close and clean up resources
        public void CloseProcess()
        {
            if (ProcessHandle != IntPtr.Zero)
            {
                CloseHandle(ProcessHandle);
                ProcessHandle = IntPtr.Zero;
            }
        }

        // Implement IDisposable to handle cleanup
        public void Dispose()
        {
            CloseProcess();
        }
    }
}
