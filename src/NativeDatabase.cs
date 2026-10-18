using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace AntonVpn
{
    internal sealed class NativeDatabase : IDisposable
    {
        private IntPtr db;
        private IntPtr library;
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr LoadLibrary(string path);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true)] private static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32")] private static extern bool FreeLibrary(IntPtr module);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Open(byte[] file, out IntPtr handle);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int HandleCall(IntPtr handle);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ExecCall(IntPtr handle, byte[] sql, IntPtr callback, IntPtr user, out IntPtr error);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void FreeCall(IntPtr error);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int PrepareCall(IntPtr handle, byte[] sql, int len, out IntPtr stmt, IntPtr tail);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindTextCall(IntPtr stmt, int index, byte[] text, int len, IntPtr destructor);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindIntCall(IntPtr stmt, int index, int value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindLongCall(IntPtr stmt, int index, long value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindDoubleCall(IntPtr stmt, int index, double value);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int BindNullCall(IntPtr stmt, int index);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate IntPtr ColumnTextCall(IntPtr stmt, int column);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int ColumnBytesCall(IntPtr stmt, int column);
        private Open sqlite3_open;
        private HandleCall sqlite3_close, sqlite3_step, sqlite3_finalize;
        private ExecCall sqlite3_exec;
        private FreeCall sqlite3_free;
        private PrepareCall sqlite3_prepare_v2;
        private BindTextCall sqlite3_bind_text;
        private BindIntCall sqlite3_bind_int;
        private BindLongCall sqlite3_bind_int64;
        private BindDoubleCall sqlite3_bind_double;
        private BindNullCall sqlite3_bind_null;
        private ColumnTextCall sqlite3_column_text;
        private ColumnBytesCall sqlite3_column_bytes;
        private T Function<T>(string name) where T : class
        {
            IntPtr pointer = GetProcAddress(library, name);
            if (pointer == IntPtr.Zero) throw new InvalidOperationException("Повреждён компонент настроек VPN.");
            return (T)(object)Marshal.GetDelegateForFunctionPointer(pointer, typeof(T));
        }
        private static byte[] Utf8(string value) { return Encoding.UTF8.GetBytes(value + "\0"); }
        private static void Check(int status) { if (status != 0) throw new InvalidOperationException("Не удалось сохранить настройки VPN. Закрой клиент и повтори."); }
        internal NativeDatabase(string clientDir)
        {
            library = LoadLibrary(Path.Combine(clientDir, "e_sqlite3.dll"));
            if (library == IntPtr.Zero) throw new InvalidOperationException("Не удалось загрузить компонент настроек.");
            try
            {
                sqlite3_open = Function<Open>("sqlite3_open");
                sqlite3_close = Function<HandleCall>("sqlite3_close");
                sqlite3_exec = Function<ExecCall>("sqlite3_exec");
                sqlite3_free = Function<FreeCall>("sqlite3_free");
                sqlite3_prepare_v2 = Function<PrepareCall>("sqlite3_prepare_v2");
                sqlite3_bind_text = Function<BindTextCall>("sqlite3_bind_text");
                sqlite3_bind_int = Function<BindIntCall>("sqlite3_bind_int");
                sqlite3_bind_int64 = Function<BindLongCall>("sqlite3_bind_int64");
                sqlite3_bind_double = Function<BindDoubleCall>("sqlite3_bind_double");
                sqlite3_bind_null = Function<BindNullCall>("sqlite3_bind_null");
                sqlite3_step = Function<HandleCall>("sqlite3_step");
                sqlite3_finalize = Function<HandleCall>("sqlite3_finalize");
                sqlite3_column_text = Function<ColumnTextCall>("sqlite3_column_text");
                sqlite3_column_bytes = Function<ColumnBytesCall>("sqlite3_column_bytes");
                Directory.CreateDirectory(Path.Combine(clientDir, "guiConfigs"));
                Check(sqlite3_open(Utf8(Path.Combine(clientDir, "guiConfigs", "guiNDB.db")), out db));
                Exec("PRAGMA busy_timeout=5000;");
            }
            catch { Dispose(); throw; }
        }
        internal void Exec(string sql)
        {
            EnsureOpen();
            IntPtr error;
            int status = sqlite3_exec(db, Utf8(sql), IntPtr.Zero, IntPtr.Zero, out error);
            if (error != IntPtr.Zero) sqlite3_free(error);
            Check(status);
        }
        internal void Upsert(string table, Dictionary<string, object> record)
        {
            EnsureOpen();
            // Identifiers are internal constants; all user-provided values are bound parameters.
            if (!Identifier(table) || record.Count == 0 || record.Keys.Any(key => !Identifier(key)))
                throw new ArgumentException("Некорректная структура настроек.");
            string sql = "INSERT OR REPLACE INTO " + table + " (" + string.Join(",", record.Keys) + ") VALUES (" +
                string.Join(",", record.Keys.Select(delegate(string key) { return "?"; })) + ");";
            IntPtr statement;
            Check(sqlite3_prepare_v2(db, Utf8(sql), -1, out statement, IntPtr.Zero));
            try
            {
                int i = 1;
                foreach (object value in record.Values)
                {
                    if (value == null) Check(sqlite3_bind_null(statement, i));
                    else if (value is bool) Check(sqlite3_bind_int(statement, i, (bool)value ? 1 : 0));
                    else if (value is int) Check(sqlite3_bind_int(statement, i, (int)value));
                    else if (value is long) Check(sqlite3_bind_int64(statement, i, (long)value));
                    else if (value is double) Check(sqlite3_bind_double(statement, i, (double)value));
                    else { byte[] bytes = Utf8((string)value); Check(sqlite3_bind_text(statement, i, bytes, bytes.Length - 1, new IntPtr(-1))); }
                    i++;
                }
                if (sqlite3_step(statement) != 101) throw new InvalidOperationException("Не удалось записать профиль VPN.");
            }
            finally { sqlite3_finalize(statement); }
        }
        private static bool Identifier(string value)
        {
            return !string.IsNullOrEmpty(value) && System.Text.RegularExpressions.Regex.IsMatch(value, "^[A-Za-z_][A-Za-z0-9_]*$");
        }
        internal string Scalar(string sql)
        {
            EnsureOpen();
            IntPtr statement;
            Check(sqlite3_prepare_v2(db, Utf8(sql), -1, out statement, IntPtr.Zero));
            try
            {
                int status = sqlite3_step(statement);
                if (status == 101) return null;
                if (status != 100) throw new InvalidOperationException("Не удалось прочитать настройки VPN.");
                IntPtr value = sqlite3_column_text(statement, 0);
                if (value == IntPtr.Zero) return null;
                byte[] bytes = new byte[sqlite3_column_bytes(statement, 0)];
                Marshal.Copy(value, bytes, 0, bytes.Length);
                return Encoding.UTF8.GetString(bytes);
            }
            finally { sqlite3_finalize(statement); }
        }
        private void EnsureOpen() { if (db == IntPtr.Zero || library == IntPtr.Zero) throw new ObjectDisposedException("NativeDatabase"); }
        public void Dispose()
        {
            if (db != IntPtr.Zero) { sqlite3_close(db); db = IntPtr.Zero; }
            // Dynamic loading is intentional: the installer must rename the staging directory
            // after configuration. DllImport would keep e_sqlite3.dll locked for this process.
            if (library != IntPtr.Zero) { FreeLibrary(library); library = IntPtr.Zero; }
        }
    }
}
