using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace RSSChecker.Scanning;

public sealed record TrustResult(
    bool IsSigned,
    bool IsValidSignature,
    bool IsTrustedPublisher,
    string Publisher,
    string SignatureSummary);

public static class TrustEvaluator
{
    static readonly ConcurrentDictionary<string, TrustResult> Cache = new(StringComparer.OrdinalIgnoreCase);

    static readonly string[] TrustedPublishers =
    [
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Valve",
        "Valve Corp.",
        "Epic Games, Inc.",
        "Easy Anti-Cheat",
        "BattlEye Innovations",
        "Riot Games",
        "FACEIT",
        "NVIDIA Corporation",
        "Advanced Micro Devices",
        "Intel Corporation",
        "Google LLC",
        "Mozilla Corporation",
        "Discord Inc.",
        "Steam",
        "Logitech",
        "Razer USA Ltd.",
        "SteelSeries ApS",
        "Corsair Memory"
    ];

    public static void ClearCache() => Cache.Clear();

    public static TrustResult Verify(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new TrustResult(false, false, false, "", "Файл не найден на диске");

        return Cache.GetOrAdd(path, VerifyInternal);
    }

    static TrustResult VerifyInternal(string path)
    {
        bool valid = VerifyAuthenticode(path);
        string publisher = ExtractPublisher(path);

        if (!valid)
        {
            // Many Windows system files (e.g. SecurityHealthSystray.exe) are catalog-signed
            // in CatRoot rather than having an embedded PE signature.
            if (VerifyCatalogSignature(path, out var catPublisher))
            {
                valid = true;
                if (string.IsNullOrWhiteSpace(publisher))
                    publisher = string.IsNullOrWhiteSpace(catPublisher) ? "Microsoft Windows" : catPublisher;
            }
        }

        // Windows catalog-signed system files in System32/SysWOW64/WinSxS
        if (valid && string.IsNullOrWhiteSpace(publisher) && IsWindowsSystemDirectory(path))
        {
            publisher = "Microsoft Windows";
        }

        if (!valid)
        {
            return new TrustResult(
                false,
                false,
                false,
                publisher,
                string.IsNullOrWhiteSpace(publisher)
                    ? "Нет цифровой подписи"
                    : $"Подпись недействительна ({publisher})");
        }

        bool trusted = !string.IsNullOrWhiteSpace(publisher) &&
                       TrustedPublishers.Any(tp => publisher.Contains(tp, StringComparison.OrdinalIgnoreCase));

        string summary = trusted
            ? $"Проверенная подпись: {publisher}"
            : $"Подписан: {(string.IsNullOrWhiteSpace(publisher) ? "Действительный сертификат" : publisher)}";

        return new TrustResult(true, true, trusted, publisher, summary);
    }

    static bool IsWindowsSystemDirectory(string path)
    {
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(winDir)) return false;

        string full = Path.GetFullPath(path);
        return full.StartsWith(Path.Combine(winDir, "System32") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(Path.Combine(winDir, "SysWOW64") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(Path.Combine(winDir, "WinSxS") + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    static string ExtractPublisher(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var cert = X509Certificate.CreateFromSignedFile(path);
            using var cert2 = new X509Certificate2(cert);
#pragma warning restore SYSLIB0057
            return cert2.GetNameInfo(X509NameType.SimpleName, false) ?? "";
        }
        catch
        {
            return "";
        }
    }

    static bool VerifyAuthenticode(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath
        };

        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = 2, // WTD_UI_NONE
            fdwRevocationChecks = 0, // WTD_REVOKE_NONE (fast offline check)
            dwUnionChoice = 1, // WTD_CHOICE_FILE
            dwStateAction = 1, // WTD_STATEACTION_VERIFY
            dwProvFlags = 0x00000080 // WTD_CACHE_ONLY_URL_RETRIEVAL
        };

        IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            trustData.pFile = fileInfoPtr;

            Guid action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            int result = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = 2; // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return result == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    static bool VerifyCatalogSignature(string filePath, out string publisher)
    {
        publisher = "";
        IntPtr catAdmin = IntPtr.Zero;
        IntPtr catInfo = IntPtr.Zero;
        try
        {
            Guid driverAction = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
            if (!CryptCATAdminAcquireContext2(out catAdmin, ref driverAction, "SHA256", IntPtr.Zero, 0))
            {
                if (!CryptCATAdminAcquireContext(out catAdmin, ref driverAction, 0))
                    return false;
            }

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            uint hashLen = 64;
            byte[] hash = new byte[hashLen];
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, fs.SafeFileHandle.DangerousGetHandle(), ref hashLen, hash, 0))
            {
                hashLen = 32;
                if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref hashLen, hash, 0))
                    return false;
            }

            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashLen, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero)
                return false;

            var infoStruct = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref infoStruct, 0))
                return false;

            string catPath = infoStruct.wszCatalogFile;
            if (string.IsNullOrWhiteSpace(catPath) || !File.Exists(catPath))
                return false;

            // Verify the catalog file itself is validly signed
            if (!VerifyAuthenticode(catPath))
                return false;

            publisher = ExtractPublisher(catPath);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (catInfo != IntPtr.Zero && catAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            if (catAdmin != IntPtr.Zero)
                CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, ref Guid pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}
