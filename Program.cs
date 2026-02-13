using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var ctx = new RandomLettersContext();
        Application.Run(ctx);
    }
}

// dotnet publish -c Release

internal sealed class RandomLettersContext : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly ToolStripMenuItem _toggleItem;
    private IntPtr _hookId = IntPtr.Zero;
    private bool _enabled = true;
    private readonly LowLevelKeyboardProc _proc;

    // -------------------------------------------------------
    // Список подменяемых букв и сдвиг на +1 по алфавиту
    //
    // Формат: "исходная" -> "замена"
    // Сдвиг на одну позицию: а->б, б->в, ..., я->а (по кругу)
    //
    // Меняй этот список как хочешь.
    // -------------------------------------------------------

    // Английские: подменяем только эти буквы, сдвиг +1
    private static readonly (char from, char to)[] MapEn = BuildShiftMap(
        "abcdefghij",   // 10 букв которые подменяем
        "abcdefghijklmnopqrstuvwxyz"  // полный алфавит для сдвига
    );

    // Русские: подменяем только эти буквы, сдвиг +1
    private static readonly (char from, char to)[] MapRu = BuildShiftMap(
        "абвгдеёжзи",   // 10 букв которые подменяем
        "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    );

    // Украинские: подменяем только эти буквы, сдвиг +1
    private static readonly (char from, char to)[] MapUk = BuildShiftMap(
        "абвгґдеєжз",   // 10 букв которые подменяем
        "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
    );

    /// <summary>
    /// Строит таблицу замен: каждая буква из subset заменяется
    /// следующей буквой в fullAlphabet (последняя -> первая).
    /// </summary>
    private static (char from, char to)[] BuildShiftMap(string subset, string fullAlphabet)
    {
        var result = new (char from, char to)[subset.Length];
        for (int i = 0; i < subset.Length; i++)
        {
            char c = subset[i];
            int idx = fullAlphabet.IndexOf(c);
            char next = idx >= 0
                ? fullAlphabet[(idx + 1) % fullAlphabet.Length]
                : c; // если не нашли — не меняем
            result[i] = (c, next);
        }
        return result;
    }

    private static readonly string LogPath = Path.Combine(AppContext.BaseDirectory, "rl_debug.log");
    private static void Log(string m) { try { File.AppendAllText(LogPath, $"{DateTime.Now:HH:mm:ss.fff} {m}\n"); } catch { } }

    public RandomLettersContext()
    {
        File.WriteAllText(LogPath, $"=== START {DateTime.Now} ===\n");
        Log($"IntPtr.Size={IntPtr.Size}");
        _proc = HookCallback;
        _toggleItem = new ToolStripMenuItem("Disable", null, (_, __) => Toggle());
        var exitItem = new ToolStripMenuItem("Exit", null, (_, __) => Exit());
        var menu = new ContextMenuStrip();
        menu.Items.Add(_toggleItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        _tray = new NotifyIcon
        {
            Visible = true,
            Text = "RandomLetters - ON",
            Icon = System.Drawing.SystemIcons.Application,
            ContextMenuStrip = menu
        };

        _hookId = SetHook(_proc);
        Log($"Hook registered: hookId={_hookId}, err={Marshal.GetLastWin32Error()}");
    }

    private void Toggle()
    {
        _enabled = !_enabled;
        _toggleItem.Text = _enabled ? "Disable" : "Enable";
        _tray.Text = _enabled ? "RandomLetters - ON" : "RandomLetters - OFF";
    }

    private void Exit()
    {
        if (_hookId != IntPtr.Zero) { UnhookWindowsHookEx(_hookId); _hookId = IntPtr.Zero; }
        _tray.Visible = false;
        _tray.Dispose();
        ExitThread();
    }

    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const int VK_SHIFT = 0x10;
    private const int VK_CONTROL = 0x11;
    private const int VK_MENU = 0x12;
    private const int VK_CAPITAL = 0x14;
    private const uint LLKHF_INJECTED = 0x00000010;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (nCode < 0) return CallNextHookEx(_hookId, nCode, wParam, lParam);
            if (!_enabled) return CallNextHookEx(_hookId, nCode, wParam, lParam);

            int msg = wParam.ToInt32();
            if (msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN)
                return CallNextHookEx(_hookId, nCode, wParam, lParam);

            var kb = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);

            if ((kb.flags & LLKHF_INJECTED) != 0)
                return CallNextHookEx(_hookId, nCode, wParam, lParam);

            if (IsDown(VK_CONTROL) || IsDown(VK_MENU))
                return CallNextHookEx(_hookId, nCode, wParam, lParam);

            if (!TryGetTypedChar(kb.vkCode, kb.scanCode, out char typed))
                return CallNextHookEx(_hookId, nCode, wParam, lParam);

            if (!char.IsLetter(typed))
                return CallNextHookEx(_hookId, nCode, wParam, lParam);

            var layout = GetActiveKeyboardLayout();
            var map = PickMap(layout);

            Log($"[KEY] vk=0x{kb.vkCode:X2} typed='{typed}'(U+{(int)typed:X4}) layout={layout}");

            if (map == null)
            {
                Log($"  [SKIP] no map for layout={layout}");
                return CallNextHookEx(_hookId, nCode, wParam, lParam);
            }

            // Ищем букву в таблице замен (сравниваем в нижнем регистре)
            char typedLower = char.ToLower(typed, CultureInfo.CurrentCulture);
            char replacement = '\0';
            foreach (var (from, to) in map)
            {
                if (from == typedLower)
                {
                    replacement = to;
                    break;
                }
            }

            // Буква не в списке подмены — пропускаем
            if (replacement == '\0')
            {
                Log($"  [SKIP] '{typed}' not in substitution list");
                return CallNextHookEx(_hookId, nCode, wParam, lParam);
            }

            // Сохраняем регистр оригинала
            bool wantUpper = char.IsUpper(typed);
            if (wantUpper)
                replacement = char.ToUpper(replacement, CultureInfo.CurrentCulture);

            // Находим VK + scan для буквы замены
            IntPtr hkl = GetActiveHkl();
            if (!TryCharToVkScan(replacement, hkl, out byte vk, out byte scan))
            {
                Log($"  [SKIP] cannot find VK for '{replacement}'(U+{(int)replacement:X4})");
                return CallNextHookEx(_hookId, nCode, wParam, lParam);
            }

            Log($"  [SEND] '{typed}'->'{replacement}'(U+{(int)replacement:X4}) vk=0x{vk:X2} scan=0x{scan:X2}");

            bool capsOn = (GetKeyState(VK_CAPITAL) & 0x01) != 0;
            bool needShift = wantUpper != capsOn;

            if (needShift) keybd_event((byte)VK_SHIFT, 0x2A, 0, UIntPtr.Zero);

            keybd_event(vk, scan, 0, UIntPtr.Zero);
            keybd_event(vk, scan, KEYEVENTF_KEYUP, UIntPtr.Zero);

            if (needShift) keybd_event((byte)VK_SHIFT, 0x2A, KEYEVENTF_KEYUP, UIntPtr.Zero);

            Log($"  [DONE] err={Marshal.GetLastWin32Error()}");
            return (IntPtr)1;
        }
        catch (Exception ex)
        {
            Log($"EXCEPTION: {ex.Message}");
            return CallNextHookEx(_hookId, nCode, wParam, lParam);
        }
    }

    private static (char from, char to)[]? PickMap(KeyboardLayout layout) => layout switch
    {
        KeyboardLayout.English => MapEn,
        KeyboardLayout.Russian => MapRu,
        KeyboardLayout.Ukrainian => MapUk,
        _ => null
    };

    private static bool TryCharToVkScan(char c, IntPtr hkl, out byte vk, out byte scan)
    {
        vk = 0; scan = 0;
        short res = VkKeyScanEx(c, hkl);
        if (res == -1) return false;
        vk = (byte)(res & 0xFF);
        uint s = MapVirtualKeyEx(vk, 0, hkl);
        scan = (byte)(s & 0xFF);
        return vk != 0;
    }

    private static IntPtr GetActiveHkl()
    {
        IntPtr hwnd = GetForegroundWindow();
        uint tid = GetWindowThreadProcessId(hwnd, IntPtr.Zero);
        return GetKeyboardLayout(tid);
    }

    private static bool IsDown(int vk) => (GetAsyncKeyState(vk) & 0x8000) != 0;

    private static bool TryGetTypedChar(uint vkCode, uint scanCode, out char ch)
    {
        ch = '\0';
        IntPtr hwnd = GetForegroundWindow();
        uint tid = GetWindowThreadProcessId(hwnd, IntPtr.Zero);
        IntPtr hkl = GetKeyboardLayout(tid);

        byte[] state = new byte[256];
        GetKeyboardState(state);
        if (vkCode < 256) state[vkCode] = 0x80;
        state[VK_SHIFT] = IsDown(VK_SHIFT) ? (byte)0x80 : (byte)0x00;
        state[VK_CONTROL] = IsDown(VK_CONTROL) ? (byte)0x80 : (byte)0x00;
        state[VK_MENU] = IsDown(VK_MENU) ? (byte)0x80 : (byte)0x00;
        state[VK_CAPITAL] = (byte)(GetKeyState(VK_CAPITAL) & 0x01);

        var sb = new StringBuilder(8);
        int rc = ToUnicodeEx(vkCode, scanCode, state, sb, sb.Capacity, 0, hkl);

        if (rc == -1)
        {
            ToUnicodeEx(vkCode, scanCode, new byte[256], new StringBuilder(8), 8, 0, hkl);
            return false;
        }
        if (rc <= 0) return false;
        ch = sb[0];
        return true;
    }

    private static KeyboardLayout GetActiveKeyboardLayout()
    {
        IntPtr hwnd = GetForegroundWindow();
        uint tid = GetWindowThreadProcessId(hwnd, IntPtr.Zero);
        IntPtr hkl = GetKeyboardLayout(tid);
        int p = ((short)((long)hkl & 0xFFFF)) & 0x3FF;
        return p switch
        {
            0x09 => KeyboardLayout.English,
            0x19 => KeyboardLayout.Russian,
            0x22 => KeyboardLayout.Ukrainian,
            _ => KeyboardLayout.Other
        };
    }

    private enum KeyboardLayout { English, Russian, Ukrainian, Other }

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode, scanCode, flags, time;
        public IntPtr dwExtraInfo;
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc)
    {
        using var p = Process.GetCurrentProcess();
        using var m = p.MainModule!;
        return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(m.ModuleName!), 0);
    }

    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr SetWindowsHookEx(int h, LowLevelKeyboardProc f, IntPtr mod, uint tid);
    [DllImport("user32.dll", SetLastError = true)]
    static extern bool UnhookWindowsHookEx(IntPtr h);
    [DllImport("user32.dll", SetLastError = true)]
    static extern IntPtr CallNextHookEx(IntPtr h, int n, IntPtr w, IntPtr l);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern IntPtr GetModuleHandle(string n);
    [DllImport("user32.dll")]
    static extern short GetKeyState(int vk);
    [DllImport("user32.dll")]
    static extern short GetAsyncKeyState(int vk);
    [DllImport("user32.dll")]
    static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("user32.dll")]
    static extern bool GetKeyboardState(byte[] s);
    [DllImport("user32.dll")]
    static extern IntPtr GetKeyboardLayout(uint tid);
    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr h, IntPtr pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern short VkKeyScanEx(char ch, IntPtr dwhkl);
    [DllImport("user32.dll")]
    static extern uint MapVirtualKeyEx(uint uCode, uint uMapType, IntPtr dwhkl);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int ToUnicodeEx(uint vk, uint sc, byte[] state,
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder buf,
        int cap, uint flags, IntPtr hkl);
}
