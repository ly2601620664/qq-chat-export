using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

internal sealed class CaptureEntry
{
    public string database { get; set; }
    public int key_length { get; set; }
    public string key_hex { get; set; }
    public string key_sha256 { get; set; }
}

internal sealed class CaptureDocument
{
    public string format { get; set; }
    public string kernel_util_sha256 { get; set; }
    public List<CaptureEntry> captures { get; set; }
}

internal static class NativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ModuleInfo
    {
        internal IntPtr BaseOfDll;
        internal uint SizeOfImage;
        internal IntPtr EntryPoint;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool SetDllDirectory(string path);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("psapi.dll", SetLastError = true)]
    internal static extern bool GetModuleInformation(
        IntPtr process,
        IntPtr module,
        out ModuleInfo moduleInfo,
        uint size);
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
internal delegate int SqliteOpenDelegate(
    [MarshalAs(UnmanagedType.LPStr)] string fileName,
    out IntPtr database);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int SqliteKeyDelegate(IntPtr database, IntPtr key, int keyLength);

[UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
internal delegate int SqliteExecDelegate(
    IntPtr database,
    [MarshalAs(UnmanagedType.LPStr)] string sql,
    IntPtr callback,
    IntPtr callbackArgument,
    out IntPtr errorMessage);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int SqliteCloseDelegate(IntPtr database);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
internal delegate int SqliteCallbackDelegate(
    IntPtr callbackArgument,
    int columnCount,
    IntPtr values,
    IntPtr columnNames);

internal static class PcqqOfflineRekey
{
    private const uint LoadWithAlteredSearchPath = 0x00000008;
    private static string callbackValue;

    private static int Main(string[] args)
    {
        if (args.Length != 7)
        {
            Console.Error.WriteLine(
                "Usage: PcqqOfflineRekey.exe <encrypted-input> <rekey-working-copy> " +
                "<standard-output> <capture-json> <key-database-path> <KernelUtil.dll> <allowed-root>");
            return 2;
        }

        string encryptedInput = Path.GetFullPath(args[0]);
        string rekeyWorkingCopy = Path.GetFullPath(args[1]);
        string standardOutput = Path.GetFullPath(args[2]);
        string captureJson = Path.GetFullPath(args[3]);
        string keyDatabasePath = args[4];
        string kernelUtilPath = Path.GetFullPath(args[5]);
        string allowedRoot = EnsureTrailingSeparator(Path.GetFullPath(args[6]));

        try
        {
            Require32BitProcess();
            RequireExistingFile(encryptedInput, "encrypted input");
            RequireExistingFile(captureJson, "capture JSON");
            RequireExistingFile(kernelUtilPath, "KernelUtil.dll");
            RequirePathInsideRoot(rekeyWorkingCopy, allowedRoot, "rekey working copy");
            RequirePathInsideRoot(standardOutput, allowedRoot, "standard output");
            if (File.Exists(rekeyWorkingCopy) || File.Exists(standardOutput))
            {
                throw new InvalidOperationException("Output path already exists; refusing to overwrite it.");
            }

            CaptureDocument capture = LoadCapture(captureJson);
            string actualKernelHash = Sha256File(kernelUtilPath);
            if (!String.Equals(capture.kernel_util_sha256, actualKernelHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("KernelUtil.dll hash does not match the capture session.");
            }

            CaptureEntry keyEntry = FindKey(capture, keyDatabasePath);
            byte[] key = HexToBytes(keyEntry.key_hex);
            if (key.Length != 16 || keyEntry.key_length != 16)
            {
                throw new InvalidOperationException("The selected PCQQ database key is not 16 bytes.");
            }
            string calculatedKeyFingerprint = Sha256Bytes(key);
            if (!String.Equals(calculatedKeyFingerprint, keyEntry.key_sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Captured key fingerprint mismatch.");
            }

            Directory.CreateDirectory(Path.GetDirectoryName(rekeyWorkingCopy));
            Directory.CreateDirectory(Path.GetDirectoryName(standardOutput));
            File.Copy(encryptedInput, rekeyWorkingCopy, false);
            string inputHash = Sha256File(encryptedInput);
            string copyHash = Sha256File(rekeyWorkingCopy);
            if (!String.Equals(inputHash, copyHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("Working copy hash differs from encrypted input.");
            }

            Console.WriteLine("INPUT_SHA256=" + inputHash);
            Console.WriteLine("WORKING_COPY_SHA256=" + copyHash);
            Console.WriteLine("KEY_FINGERPRINT=" + calculatedKeyFingerprint.Substring(0, 12));
            Console.WriteLine("KERNEL_SHA256=" + actualKernelHash);

            int rekeyResult = RekeyDatabase(rekeyWorkingCopy, kernelUtilPath, key);
            if (rekeyResult != 0)
            {
                return rekeyResult;
            }

            RequireHeaders(rekeyWorkingCopy);
            StripExtendedHeader(rekeyWorkingCopy, standardOutput, 1024);
            Console.WriteLine("REKEYED_SHA256=" + Sha256File(rekeyWorkingCopy));
            Console.WriteLine("STANDARD_SHA256=" + Sha256File(standardOutput));
            Console.WriteLine("STANDARD_SIZE=" + new FileInfo(standardOutput).Length);
            Console.WriteLine("RESULT=ok");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("ERROR=" + error.GetType().Name + ": " + error.Message);
            return 1;
        }
    }

    private static int RekeyDatabase(string databasePath, string kernelUtilPath, byte[] key)
    {
        string kernelDirectory = Path.GetDirectoryName(kernelUtilPath);
        if (!NativeMethods.SetDllDirectory(kernelDirectory))
        {
            throw new InvalidOperationException(
                "SetDllDirectory failed with Win32 error " + Marshal.GetLastWin32Error() + ".");
        }

        IntPtr module = NativeMethods.LoadLibraryEx(
            kernelUtilPath,
            IntPtr.Zero,
            LoadWithAlteredSearchPath);
        if (module == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "LoadLibraryEx failed with Win32 error " + Marshal.GetLastWin32Error() + ".");
        }

        IntPtr database = IntPtr.Zero;
        try
        {
            NativeMethods.ModuleInfo moduleInfo;
            if (!NativeMethods.GetModuleInformation(
                NativeMethods.GetCurrentProcess(),
                module,
                out moduleInfo,
                (uint)Marshal.SizeOf(typeof(NativeMethods.ModuleInfo))))
            {
                throw new InvalidOperationException(
                    "GetModuleInformation failed with Win32 error " + Marshal.GetLastWin32Error() + ".");
            }

            byte[] image = new byte[moduleInfo.SizeOfImage];
            Marshal.Copy(moduleInfo.BaseOfDll, image, 0, image.Length);

            IntPtr openAddress = FindUnique(
                moduleInfo.BaseOfDll,
                image,
                "55 8B EC 6A 00 6A 06 FF 75 0C FF 75 08 E8 ?? ?? ?? ??",
                "sqlite3_open");
            IntPtr execAddress = FindUnique(
                moduleInfo.BaseOfDll,
                image,
                "55 8B EC 83 EC 20 53 56 8B 75 08 33 DB 21 5D FC 56",
                "sqlite3_exec");
            IntPtr keyAddress = FindUnique(
                moduleInfo.BaseOfDll,
                image,
                "55 8B EC 56 6B 75 10 11 83 7D 10 10 74 0D 68 17 02 00 00 E8",
                "sqlite3_key");
            IntPtr rekeyAddress = FindUnique(
                moduleInfo.BaseOfDll,
                image,
                "55 8B EC 83 7D 10 10 74 0D 68 2F 02 00 00 E8",
                "sqlite3_rekey");
            IntPtr closeAddress = FindUnique(
                moduleInfo.BaseOfDll,
                image,
                "55 8B EC 6A 00 FF 75 08 E8 2A E0 02 00 59 59 5D C3",
                "sqlite3_close");

            SqliteOpenDelegate open = (SqliteOpenDelegate)Marshal.GetDelegateForFunctionPointer(
                openAddress,
                typeof(SqliteOpenDelegate));
            SqliteExecDelegate exec = (SqliteExecDelegate)Marshal.GetDelegateForFunctionPointer(
                execAddress,
                typeof(SqliteExecDelegate));
            SqliteKeyDelegate setKey = (SqliteKeyDelegate)Marshal.GetDelegateForFunctionPointer(
                keyAddress,
                typeof(SqliteKeyDelegate));
            SqliteKeyDelegate rekey = (SqliteKeyDelegate)Marshal.GetDelegateForFunctionPointer(
                rekeyAddress,
                typeof(SqliteKeyDelegate));
            SqliteCloseDelegate close = (SqliteCloseDelegate)Marshal.GetDelegateForFunctionPointer(
                closeAddress,
                typeof(SqliteCloseDelegate));

            int result = open(databasePath, out database);
            Console.WriteLine("OPEN_RC=" + result);
            if (result != 0 || database == IntPtr.Zero)
            {
                return 10;
            }

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);
            try
            {
                result = setKey(database, keyHandle.AddrOfPinnedObject(), key.Length);
            }
            finally
            {
                keyHandle.Free();
            }
            Console.WriteLine("KEY_RC=" + result);
            if (result != 0)
            {
                return 11;
            }

            IntPtr errorMessage;
            result = exec(
                database,
                "SELECT count(*) FROM sqlite_master;",
                IntPtr.Zero,
                IntPtr.Zero,
                out errorMessage);
            Console.WriteLine("KEY_VALIDATION_RC=" + result);
            if (result != 0)
            {
                Console.Error.WriteLine("KEY_VALIDATION=failed; database copy was not rekeyed");
                return 20;
            }

            byte[] emptyKey = new byte[16];
            GCHandle emptyHandle = GCHandle.Alloc(emptyKey, GCHandleType.Pinned);
            try
            {
                result = rekey(database, emptyHandle.AddrOfPinnedObject(), emptyKey.Length);
            }
            finally
            {
                emptyHandle.Free();
            }
            Console.WriteLine("REKEY_RC=" + result);
            if (result != 0)
            {
                return 21;
            }

            callbackValue = null;
            SqliteCallbackDelegate callback = new SqliteCallbackDelegate(CaptureFirstValue);
            IntPtr callbackAddress = Marshal.GetFunctionPointerForDelegate(callback);
            result = exec(
                database,
                "PRAGMA quick_check;",
                callbackAddress,
                IntPtr.Zero,
                out errorMessage);
            GC.KeepAlive(callback);
            Console.WriteLine("POST_REKEY_QUICK_CHECK_RC=" + result);
            Console.WriteLine("POST_REKEY_QUICK_CHECK=" + (callbackValue ?? "<null>"));
            if (result != 0 || !String.Equals(callbackValue, "ok", StringComparison.OrdinalIgnoreCase))
            {
                return 22;
            }

            result = close(database);
            database = IntPtr.Zero;
            Console.WriteLine("CLOSE_RC=" + result);
            if (result != 0)
            {
                return 23;
            }
            return 0;
        }
        finally
        {
            if (database != IntPtr.Zero)
            {
                try
                {
                    // The isolated helper process exits immediately even if close cannot be resolved.
                }
                catch
                {
                }
            }
            NativeMethods.FreeLibrary(module);
            NativeMethods.SetDllDirectory(null);
        }
    }

    private static int CaptureFirstValue(
        IntPtr callbackArgument,
        int columnCount,
        IntPtr values,
        IntPtr columnNames)
    {
        if (columnCount > 0 && values != IntPtr.Zero)
        {
            IntPtr value = Marshal.ReadIntPtr(values, 0);
            callbackValue = value == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(value);
        }
        return 0;
    }

    private static IntPtr FindUnique(
        IntPtr moduleBase,
        byte[] image,
        string patternText,
        string label)
    {
        string[] tokens = patternText.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        int[] pattern = new int[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            pattern[i] = tokens[i] == "??" ? -1 : Convert.ToInt32(tokens[i], 16);
        }

        int foundOffset = -1;
        int matches = 0;
        for (int offset = 0; offset <= image.Length - pattern.Length; offset++)
        {
            bool matched = true;
            for (int index = 0; index < pattern.Length; index++)
            {
                if (pattern[index] >= 0 && image[offset + index] != (byte)pattern[index])
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
            {
                matches++;
                foundOffset = offset;
            }
        }

        Console.WriteLine(label.ToUpperInvariant() + "_MATCH_COUNT=" + matches);
        if (matches != 1)
        {
            throw new InvalidOperationException(label + " signature matched " + matches + " locations.");
        }
        return IntPtr.Add(moduleBase, foundOffset);
    }

    private static CaptureDocument LoadCapture(string path)
    {
        string json = File.ReadAllText(path, Encoding.UTF8);
        CaptureDocument capture = new JavaScriptSerializer().Deserialize<CaptureDocument>(json);
        if (capture == null || capture.format != "pcqq-sqlite-key-capture-v1" || capture.captures == null)
        {
            throw new InvalidDataException("Unsupported or invalid capture JSON.");
        }
        return capture;
    }

    private static CaptureEntry FindKey(CaptureDocument capture, string databasePath)
    {
        CaptureEntry found = null;
        foreach (CaptureEntry entry in capture.captures)
        {
            if (entry != null && String.Equals(
                entry.database,
                databasePath,
                StringComparison.OrdinalIgnoreCase))
            {
                found = entry;
            }
        }
        if (found == null)
        {
            throw new InvalidDataException("Requested database key was not present in the capture JSON.");
        }
        return found;
    }

    private static void RequireHeaders(string path)
    {
        byte[] header = new byte[1040];
        using (FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            int read = stream.Read(header, 0, header.Length);
            if (read != header.Length)
            {
                throw new InvalidDataException("Rekeyed file is too short for PCQQ extended headers.");
            }
        }
        string extended = Encoding.ASCII.GetString(header, 0, 16);
        string sqlite = Encoding.ASCII.GetString(header, 1024, 16);
        Console.WriteLine("EXTENDED_HEADER=" + extended.Replace("\0", "\\0"));
        Console.WriteLine("SQLITE_HEADER_AT_1024=" + sqlite.Replace("\0", "\\0"));
        if (extended != "SQLite header 3\0" || sqlite != "SQLite format 3\0")
        {
            throw new InvalidDataException("Expected decrypted SQLite header was not found at offset 1024.");
        }
    }

    private static void StripExtendedHeader(string input, string output, int headerLength)
    {
        byte[] buffer = new byte[1024 * 1024];
        using (FileStream source = File.Open(input, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (FileStream destination = File.Open(output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            source.Position = headerLength;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                destination.Write(buffer, 0, read);
            }
            destination.Flush(true);
        }
    }

    private static byte[] HexToBytes(string hex)
    {
        if (String.IsNullOrEmpty(hex) || hex.Length % 2 != 0)
        {
            throw new InvalidDataException("Captured key hex is invalid.");
        }
        byte[] value = new byte[hex.Length / 2];
        for (int i = 0; i < value.Length; i++)
        {
            value[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return value;
    }

    private static string Sha256File(string path)
    {
        using (SHA256 algorithm = SHA256.Create())
        using (FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            return ToHex(algorithm.ComputeHash(stream));
        }
    }

    private static string Sha256Bytes(byte[] value)
    {
        using (SHA256 algorithm = SHA256.Create())
        {
            return ToHex(algorithm.ComputeHash(value));
        }
    }

    private static string ToHex(byte[] value)
    {
        StringBuilder result = new StringBuilder(value.Length * 2);
        foreach (byte item in value)
        {
            result.Append(item.ToString("x2"));
        }
        return result.ToString();
    }

    private static void RequireExistingFile(string path, string label)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(label + " was not found.", path);
        }
    }

    private static void Require32BitProcess()
    {
        if (IntPtr.Size != 4)
        {
            throw new PlatformNotSupportedException("This helper must run as a 32-bit process.");
        }
    }

    private static string EnsureTrailingSeparator(string path)
    {
        return path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private static void RequirePathInsideRoot(string path, string root, string label)
    {
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(label + " must stay inside the allowed work root.");
        }
    }
}
