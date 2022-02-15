using System;
using System.Runtime.InteropServices;

namespace AdjustPriv
{
    class Program
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name,ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        public static bool AdjustPriv(IntPtr hproc,string Privilege)
        {
            try
            {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, Privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                CloseHandle(htok);
                return retVal;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }
        //https://www.pinvoke.net/default.aspx/advapi32/AdjustTokenPrivileges.html
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: " + AppDomain.CurrentDomain.FriendlyName + " PID");
                Environment.Exit(1);
            }
            int PID = int.Parse(args[0]);
            IntPtr hProcess;
            hProcess = OpenProcess(0x001F0FFF, false, PID);
            if (hProcess == null)
            {
                Console.WriteLine("Can't not open Process");
                Environment.Exit(2);
            }

            foreach (string sSEPrivilegeName in Enum.GetNames(typeof(Privileges)))
            {
                if (!AdjustPriv(hProcess, sSEPrivilegeName))
                {
                    Console.WriteLine("AdjustTokenPrivileges failed, error = {0}. {1} is not available", Marshal.GetLastWin32Error(), sSEPrivilegeName);
                }
                else
                {
                    Console.WriteLine("AdjustTokenPrivileges successfully, {0} is available", sSEPrivilegeName);
                }
            }
        }
    }
}
