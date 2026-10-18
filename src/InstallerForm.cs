using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AntonVpn
{
    internal sealed class InstallerForm : Form
    {
        private readonly bool settings;
        private readonly TextBox link;
        private readonly CheckBox autoRun;
        private readonly CheckBox reveal;
        private readonly Button action;
        private readonly Button close;
        private readonly Label status;
        private readonly ProgressBar progress;
        private bool busy, complete;
        private readonly Color ink = Color.FromArgb(27, 42, 62);

        internal InstallerForm(bool settingsMode)
        {
            SuspendLayout();
            settings = settingsMode;
            Text = settings ? "Настроить VPN" : "Мой VPN — установка";
            ClientSize = new Size(600, 544);
            Font = new Font("Segoe UI", 10F);
            BackColor = Color.White;
            ForeColor = ink;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;

            var top = new Panel { Location = new Point(0, 0), Size = new Size(600, 112), BackColor = Color.FromArgb(21, 39, 58) };
            top.Controls.Add(new Label { Text = "Мой VPN", ForeColor = Color.White, Font = new Font("Segoe UI", 24F, FontStyle.Bold), Location = new Point(28, 16), AutoSize = true });
            top.Controls.Add(new Label { Text = settings ? "Замена личной ссылки и настройка запуска" : "Подключение на этом компьютере за несколько шагов", ForeColor = Color.FromArgb(201, 217, 228), Location = new Point(30, 71), AutoSize = true });
            Controls.Add(top);
            Controls.Add(LabelAt("1   Вставь личную ссылку подключения", 28, 136, true));
            Controls.Add(new Label { Text = "Получи у Антона свою ссылку, которая начинается с vless://.", Location = new Point(28, 170), Size = new Size(548, 28), ForeColor = Color.FromArgb(93, 109, 126) });
            link = new TextBox { Location = new Point(30, 203), Size = new Size(540, 30), UseSystemPasswordChar = true, MaxLength = 8192, Font = new Font("Segoe UI", 11F), ShortcutsEnabled = true };
            Controls.Add(link);
            reveal = new CheckBox { Text = "Показать ссылку", Location = new Point(30, 240), AutoSize = true, ForeColor = Color.FromArgb(93, 109, 126) };
            reveal.CheckedChanged += delegate { link.UseSystemPasswordChar = !reveal.Checked; };
            Controls.Add(reveal);
            Controls.Add(LabelAt("2   Выбери запуск", 28, 284, true));
            autoRun = new CheckBox { Text = "Включать VPN при входе в Windows", Checked = true, Location = new Point(30, 319), AutoSize = true };
            Controls.Add(autoRun);
            Controls.Add(new Label {
                Text = "Через VPN: ChatGPT, Claude, YouTube, Instagram и Telegram.\r\nGoogle и остальные сайты работают напрямую.",
                Location = new Point(30, 360), Size = new Size(540, 48), ForeColor = Color.FromArgb(93, 109, 126), Font = new Font("Segoe UI", 9F)
            });
            status = new Label { Text = "Сначала проверим подключение по твоей ссылке.", Location = new Point(30, 418), Size = new Size(540, 40), ForeColor = Color.FromArgb(93, 109, 126), Font = new Font("Segoe UI", 9F) };
            Controls.Add(status);
            progress = new ProgressBar { Location = new Point(30, 459), Size = new Size(540, 5), Style = ProgressBarStyle.Continuous };
            Controls.Add(progress);
            action = new Button {
                Text = settings ? "Сохранить и проверить" : "Установить VPN", Location = new Point(285, 484), Size = new Size(285, 40),
                BackColor = Color.FromArgb(6, 115, 119), ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand
            };
            action.FlatAppearance.BorderSize = 0;
            action.Click += OnAction;
            close = new Button { Text = "Закрыть", Location = new Point(30, 484), Size = new Size(110, 40), FlatStyle = FlatStyle.Flat, BackColor = Color.White };
            close.FlatAppearance.BorderColor = Color.FromArgb(219, 225, 231);
            close.Click += delegate { Close(); };
            Controls.Add(action); Controls.Add(close);
            AcceptButton = action;
            FormClosing += delegate(object sender, FormClosingEventArgs e) { if (busy) e.Cancel = true; };
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            ResumeLayout(true);
            Shown += delegate {
                Rectangle work = Screen.FromControl(this).WorkingArea;
                if (Height > work.Height - 24)
                {
                    Size content = ClientSize;
                    AutoScroll = true;
                    AutoScrollMinSize = content;
                    Height = work.Height - 24;
                    Top = work.Top + 12;
                }
            };
        }

        private Label LabelAt(string text, int x, int y, bool bold)
        {
            return new Label { Text = text, Location = new Point(x, y), AutoSize = true, Font = new Font("Segoe UI", 12F, bold ? FontStyle.Bold : FontStyle.Regular) };
        }

        private void UpdateProgress(int value, string text)
        {
            if (IsDisposed) return;
            if (InvokeRequired) { BeginInvoke(new Action<int, string>(UpdateProgress), value, text); return; }
            progress.Value = Math.Max(0, Math.Min(100, value));
            status.Text = text;
        }

        private async void OnAction(object sender, EventArgs e)
        {
            if (busy) return;
            if (complete)
            {
                try
                {
                    if (!InstallService.Launch()) throw new InvalidOperationException("Не удалось запустить VPN. Открой «Мой VPN» на рабочем столе.");
                    Close();
                }
                catch (Exception error) { ShowError(error); }
                return;
            }
            string personalLink = link.Text;
            try { VlessLink.Parse(personalLink); }
            catch (Exception error) { ShowError(error); link.Focus(); return; }
            busy = true;
            action.Enabled = close.Enabled = link.Enabled = reveal.Enabled = autoRun.Enabled = false;
            bool enableAutoRun = autoRun.Checked;
            try
            {
                await Task.Run(delegate {
                    if (settings) InstallService.Configure(personalLink, enableAutoRun, UpdateProgress);
                    else InstallService.Install(personalLink, enableAutoRun, UpdateProgress);
                });
                link.Clear(); personalLink = null;
                complete = true;
                progress.Value = 100;
                status.ForeColor = Color.FromArgb(6, 115, 119);
                status.Text = "Готово. Подключение проверено.\r\nОткрывать VPN можно ярлыком «Мой VPN» на рабочем столе.";
                action.Text = "Включить VPN";
            }
            catch (Exception error) { ShowError(error); }
            finally
            {
                busy = false;
                action.Enabled = close.Enabled = true;
                link.Enabled = reveal.Enabled = autoRun.Enabled = !complete;
            }
        }

        private void ShowError(Exception error)
        {
            string text = error is ArgumentException || error is InvalidOperationException ? error.Message :
                "Не удалось завершить установку. Закрой другой VPN и повтори. Если ошибка сохраняется, обратись к Антону.";
            status.ForeColor = Color.FromArgb(155, 73, 34);
            status.Text = text;
            MessageBox.Show(this, text, "Мой VPN", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
