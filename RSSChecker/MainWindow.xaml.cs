using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using RSSChecker.Models;
using RSSChecker.Scanning;
using RSSChecker.Services;

namespace RSSChecker;

public partial class MainWindow : Window
{
    readonly AppDataService store = new();
    readonly ObservableCollection<Finding> findings = [];
    readonly CancellationTokenSource lifetime = new();
    readonly List<Snowflake> snowflakes = [];
    readonly Stopwatch snowClock = new();
    readonly Random rng = new();

    AppSettings settings = new();
    ScanReport? latest;
    ICollectionView? resultsView;
    CancellationTokenSource? scanCts;
    ScanContext? activeScanCtx;
    DispatcherTimer? scanUiTimer;
    int scanTickCount;
    bool scanning;
    bool fullMode;
    bool isRussian = true;
    double lastSnowTime;
    string selectedPath = "";

    sealed class Snowflake
    {
        public required Ellipse Shape { get; init; }
        public double X { get; set; }
        public double Y { get; set; }
        public double SpeedY { get; init; }
        public double SwayAmp { get; init; }
        public double SwayFreq { get; init; }
        public double Phase { get; init; }
    }

    public MainWindow()
    {
        InitializeComponent();

        resultsView = CollectionViewSource.GetDefaultView(findings);
        resultsView.Filter = FilterFinding;
        ResultsGrid.ItemsSource = resultsView;

        StateChanged += OnWindowStateChanged;
        Loaded += OnLoaded;
        Closed += (_, _) =>
        {
            CompositionTarget.Rendering -= OnSnowFrame;
            scanCts?.Cancel();
            lifetime.Cancel();
        };
    }

    async void OnLoaded(object? sender, RoutedEventArgs e)
    {
        InitSnow();
        snowClock.Start();
        CompositionTarget.Rendering += OnSnowFrame;

        settings = await store.LoadSettingsAsync();
        if (string.IsNullOrWhiteSpace(settings.Language))
            settings.Language = "Русский";

        // Default to Russian for everyday users unless explicitly switched to English
        isRussian = settings.Language != "English";
        ApplyLanguage();
        UpdateNavHighlight(NavScanBtn);
        UpdateModeCards();

        await RefreshHistoryAsync();
    }

    #region Custom Frameless Window Controls

    void OnWindowStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowFrame.Margin = new Thickness(0);
            WindowFrame.CornerRadius = new CornerRadius(0);
            MaxBtn.Content = "❐";
        }
        else
        {
            WindowFrame.Margin = new Thickness(12);
            WindowFrame.CornerRadius = new CornerRadius(22);
            MaxBtn.Content = "□";
        }
    }

    void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    void Close_Click(object sender, RoutedEventArgs e)
    {
        var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(160))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
        };
        fade.Completed += (_, _) => Close();
        WindowFrame.BeginAnimation(OpacityProperty, fade);
    }

    #endregion

    #region Snowfall Engine

    void InitSnow()
    {
        SnowCanvas.Children.Clear();
        snowflakes.Clear();

        double w = ActualWidth > 100 ? ActualWidth : 1180;
        double h = ActualHeight > 100 ? ActualHeight : 780;

        for (int i = 0; i < 58; i++)
        {
            double size = 2.0 + rng.NextDouble() * 3.8;
            double opacity = 0.22 + (size - 2.0) / 3.8 * 0.52;

            var flake = new Ellipse
            {
                Width = size,
                Height = size,
                Fill = new SolidColorBrush(Color.FromArgb((byte)(opacity * 255), 235, 244, 255)),
                IsHitTestVisible = false
            };

            var sf = new Snowflake
            {
                Shape = flake,
                X = rng.NextDouble() * w,
                Y = rng.NextDouble() * h,
                SpeedY = 18 + (size * 8.5) + rng.NextDouble() * 14,
                SwayAmp = 8 + rng.NextDouble() * 16,
                SwayFreq = 0.6 + rng.NextDouble() * 1.1,
                Phase = rng.NextDouble() * Math.PI * 2
            };

            Canvas.SetLeft(flake, sf.X);
            Canvas.SetTop(flake, sf.Y);
            SnowCanvas.Children.Add(flake);
            snowflakes.Add(sf);
        }
    }

    void OnSnowFrame(object? sender, EventArgs e)
    {
        double now = snowClock.Elapsed.TotalSeconds;
        double dt = Math.Min(now - lastSnowTime, 0.05);
        lastSnowTime = now;
        if (dt <= 0) return;

        double w = SnowCanvas.ActualWidth;
        double h = SnowCanvas.ActualHeight;
        if (w <= 0 || h <= 0) return;

        foreach (var sf in snowflakes)
        {
            sf.Y += sf.SpeedY * dt;
            double x = sf.X + Math.Sin(now * sf.SwayFreq + sf.Phase) * sf.SwayAmp;

            if (sf.Y > h + 8)
            {
                sf.Y = -8;
                sf.X = rng.NextDouble() * w;
                x = sf.X;
            }

            Canvas.SetLeft(sf.Shape, x);
            Canvas.SetTop(sf.Shape, sf.Y);
        }
    }

    #endregion

    #region Navigation & Windows 11 Animations

    void NavScan_Click(object sender, RoutedEventArgs e) => Navigate(ScanPage, ScanPageSlide, NavScanBtn);
    void NavResults_Click(object sender, RoutedEventArgs e) => Navigate(ResultsPage, ResultsPageSlide, NavResultsBtn);
    void NavHistory_Click(object sender, RoutedEventArgs e) => Navigate(HistoryPage, HistoryPageSlide, NavHistoryBtn);

    void Navigate(FrameworkElement page, TranslateTransform slide, Button activeNav)
    {
        UpdateNavHighlight(activeNav);

        if (page.Visibility == Visibility.Visible) return;

        ScanPage.Visibility = Visibility.Collapsed;
        ResultsPage.Visibility = Visibility.Collapsed;
        HistoryPage.Visibility = Visibility.Collapsed;

        page.Visibility = Visibility.Visible;
        page.Opacity = 0;
        slide.Y = 16;

        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        page.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(240)) { EasingFunction = ease });
        slide.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(16, 0, TimeSpan.FromMilliseconds(280)) { EasingFunction = ease });
    }

    void UpdateNavHighlight(Button active)
    {
        var transparent = Brushes.Transparent;
        var activeBg = (Brush)FindResource("GlassFillActive");
        var activeBorder = (Brush)FindResource("GlassBorderBrush");
        var textPrimary = (Brush)FindResource("TextPrimary");
        var textSecondary = (Brush)FindResource("TextSecondary");

        foreach (var btn in new[] { NavScanBtn, NavResultsBtn, NavHistoryBtn })
        {
            bool isSelected = btn == active;
            btn.Background = isSelected ? activeBg : transparent;
            btn.BorderBrush = isSelected ? activeBorder : transparent;
            btn.Foreground = isSelected ? textPrimary : textSecondary;
        }
    }

    void AnimateProgress(double target)
    {
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        Progress.BeginAnimation(ProgressBar.ValueProperty,
            new DoubleAnimation(Progress.Value, target, TimeSpan.FromMilliseconds(360)) { EasingFunction = ease });
        PercentText.Text = $"{Math.Round(target)}%";
    }

    void StartScanPulse()
    {
        var pulse = new DoubleAnimation(0.55, 1.0, TimeSpan.FromMilliseconds(850))
        {
            AutoReverse = true,
            RepeatBehavior = RepeatBehavior.Forever,
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        StatusOrb.BeginAnimation(OpacityProperty, pulse);

        ScanRing.Visibility = Visibility.Visible;
        var spin = new DoubleAnimation(0, 360, TimeSpan.FromSeconds(1.4))
        {
            RepeatBehavior = RepeatBehavior.Forever
        };
        ScanRingRotate.BeginAnimation(RotateTransform.AngleProperty, spin);

        scanTickCount = 0;
        scanUiTimer?.Stop();
        scanUiTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        scanUiTimer.Tick += (_, _) =>
        {
            if (!scanning || activeScanCtx == null) return;
            scanTickCount++;

            string[] ruPhrases =
            [
                "Идёт проверка системы…",
                "Проверяем файлы и подписи…",
                "Анализируем запущенные процессы…",
                "Ищем следы в Prefetch и реестре…",
                "Сверяем сигнатуры читов…"
            ];
            string[] enPhrases =
            [
                "Scanning system…",
                "Verifying files and signatures…",
                "Analyzing running processes…",
                "Checking Prefetch and registry traces…",
                "Matching cheat signatures…"
            ];

            int checkedNow = activeScanCtx.Report.ObjectsChecked;
            LastScanText.Text = isRussian
                ? $"Проверено объектов: {checkedNow:N0}…"
                : $"Objects checked: {checkedNow:N0}…";

            if (scanTickCount % 7 == 0)
            {
                var list = isRussian ? ruPhrases : enPhrases;
                int idx = (scanTickCount / 7) % list.Length;
                ProtectionText.Text = list[idx];
                ProtectionText.Opacity = 0.45;
                ProtectionText.BeginAnimation(OpacityProperty,
                    new DoubleAnimation(0.45, 1.0, TimeSpan.FromMilliseconds(280))
                    {
                        EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
                    });
            }
        };
        scanUiTimer.Start();
    }

    void StopScanPulse()
    {
        scanUiTimer?.Stop();
        StatusOrb.BeginAnimation(OpacityProperty, null);
        StatusOrb.Opacity = 1.0;

        ScanRingRotate.BeginAnimation(RotateTransform.AngleProperty, null);
        ScanRing.Visibility = Visibility.Collapsed;
    }

    #endregion

    #region Mode Selection & Scanning

    void SelectQuickMode_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (scanning) return;
        fullMode = false;
        UpdateModeCards();
    }

    void SelectFullMode_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (scanning) return;
        fullMode = true;
        UpdateModeCards();
    }

    void UpdateModeCards()
    {
        var activeBg = (Brush)FindResource("GlassFillActive");
        var normalBg = (Brush)FindResource("GlassFill");
        var accent = (Brush)FindResource("Accent");
        var normalBorder = (Brush)FindResource("GlassBorderBrush");

        QuickModeCard.Background = !fullMode ? activeBg : normalBg;
        QuickModeCard.BorderBrush = !fullMode ? accent : normalBorder;
        QuickModeCard.BorderThickness = new Thickness(!fullMode ? 1.5 : 1);

        FullModeCard.Background = fullMode ? activeBg : normalBg;
        FullModeCard.BorderBrush = fullMode ? accent : normalBorder;
        FullModeCard.BorderThickness = new Thickness(fullMode ? 1.5 : 1);
    }

    async void ScanAction_Click(object sender, RoutedEventArgs e)
    {
        if (scanning)
        {
            scanCts?.Cancel();
            return;
        }
        await RunScan(fullMode);
    }

    async Task RunScan(bool full)
    {
        if (scanning) return;
        scanning = true;
        scanCts = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);

        findings.Clear();
        UpdateEmptyState();
        ViewResultsBtn.Visibility = Visibility.Collapsed;

        latest = new ScanReport
        {
            Mode = full
                ? (isRussian ? "Полная проверка" : "Full scan")
                : (isRussian ? "Быстрая проверка" : "Quick scan")
        };

        Progress.BeginAnimation(ProgressBar.ValueProperty, null);
        Progress.Value = 0;
        PercentText.Text = "0%";
        StatusIcon.Text = "⏳";
        ProtectionText.Text = isRussian ? "Идёт проверка…" : "Scanning your device…";
        LastScanText.Text = isRussian ? "Пожалуйста, подождите немного" : "Please wait a moment";
        PhaseText.Text = isRussian ? "Подготовка…" : "Preparing…";
        ScanActionBtn.Content = isRussian ? "Остановить" : "Stop scan";
        StartScanPulse();

        try
        {
            TrustEvaluator.ClearCache();
            var db = await store.LoadDatabaseAsync();
            IScanner[] scanners = full
                ? [
                    new ProcessScanner(settings.Exclusions),
                    new FileSystemScanner(true, settings.Exclusions, settings.ScanSensitivity),
                    new PersistenceScanner(),
                    new GameIntegrityScanner(),
                    new SecurityArtifactsScanner()
                  ]
                : [
                    new ProcessScanner(settings.Exclusions),
                    new FileSystemScanner(false, settings.Exclusions, settings.ScanSensitivity),
                    new PersistenceScanner(),
                    new SecurityArtifactsScanner()
                  ];

            var scanCtx = new ScanContext(latest, db, new Progress<(string Phase, int Percent)>(_ => { }));
            activeScanCtx = scanCtx;

            await Task.Run(async () =>
            {
                for (int i = 0; i < scanners.Length; i++)
                {
                    scanCts.Token.ThrowIfCancellationRequested();
                    string stepName = LocalizeScannerName(scanners[i].Name);

                    await Dispatcher.InvokeAsync(() =>
                    {
                        PhaseText.Text = $"{stepName} ({i + 1}/{scanners.Length})";
                    });

                    await scanners[i].ScanAsync(scanCtx, scanCts.Token);

                    await Dispatcher.InvokeAsync(() =>
                    {
                        SyncFindingsSorted(latest.Findings);
                        AnimateProgress((i + 1) * 100.0 / scanners.Length);
                    });
                }
            }, scanCts.Token);

            latest.FinishedAt = DateTimeOffset.Now;
            SyncFindingsSorted(latest.Findings);
            UpdateEmptyState();
            await store.SaveHistoryAsync(latest);
            await RefreshHistoryAsync();
            await RefreshOverviewAsync();

            PhaseText.Text = isRussian ? "Проверка завершена" : "Scan complete";
            int threats = latest.Findings.Count(x => x.Status is DetectionStatus.CheatDetected or DetectionStatus.HighRisk);
            int suspicious = latest.Findings.Count(x => x.Status == DetectionStatus.Suspicious);

            if (threats == 0 && suspicious == 0)
            {
                StatusIcon.Text = "✓";
                ProtectionText.Text = isRussian ? "Угроз не обнаружено" : "No threats found";
            }
            else
            {
                StatusIcon.Text = "!";
                ProtectionText.Text = isRussian
                    ? $"Обнаружено: угроз — {threats}, подозрительных — {suspicious}"
                    : $"Found: {threats} threat(s), {suspicious} suspicious";
                ViewResultsBtn.Visibility = Visibility.Visible;
            }
        }
        catch (OperationCanceledException)
        {
            StatusIcon.Text = "🛡";
            PhaseText.Text = isRussian ? "Проверка остановлена" : "Scan cancelled";
            ProtectionText.Text = isRussian ? "Проверка прервана" : "Scan stopped";
        }
        catch (Exception ex)
        {
            StatusIcon.Text = "!";
            PhaseText.Text = isRussian ? "Ошибка проверки" : "Scan error";
            ProtectionText.Text = ex.Message;
        }
        finally
        {
            StopScanPulse();
            scanning = false;
            ScanActionBtn.Content = isRussian ? "Начать проверку" : "Start scan";
        }
    }

    string LocalizeScannerName(string name)
    {
        if (!isRussian) return name;
        return name switch
        {
            "Processes" => "Проверка запущенных программ",
            "File System" => "Проверка файлов",
            "Persistence" => "Проверка автозагрузки",
            "Game Integrity" => "Проверка целостности",
            "Security Artifacts" => "Проверка системных следов",
            "Traces & artifacts" => "Проверка следов запуска",
            _ => name
        };
    }

    #endregion

    #region Results, History & Language

    void Filters_Changed(object sender, RoutedEventArgs e)
    {
        resultsView?.Refresh();
        UpdateEmptyState();
    }

    void SyncFindingsSorted(IEnumerable<Finding> source)
    {
        var sorted = source
            .OrderBy(f => f.StatusSortOrder)
            .ThenByDescending(f => f.RiskScore)
            .ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        findings.Clear();
        foreach (var item in sorted)
            findings.Add(item);
    }

    bool FilterFinding(object item)
    {
        if (item is not Finding f) return false;
        string q = SearchBox?.Text?.Trim() ?? "";
        if (q.Length > 0 && !$"{f.Name} {f.Path} {f.Category} {f.Sha256} {f.DetectedTool}".Contains(q, StringComparison.OrdinalIgnoreCase))
            return false;

        string status = (StatusFilter?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
        if (string.IsNullOrEmpty(status) || status == "Все статусы" || status == "All statuses")
            return true;

        return status.Equals(f.StatusDisplay, StringComparison.OrdinalIgnoreCase);
    }

    void Finding_Selected(object sender, SelectionChangedEventArgs e)
    {
        if (ResultsGrid.SelectedItem is not Finding f) return;
        selectedPath = f.Path;
        DetailName.Text = string.IsNullOrWhiteSpace(f.DetectedTool) ? f.Name : $"{f.Name} ({f.DetectedTool})";
        DetailStatus.Text = $"{f.StatusDisplay} · Риск: {f.RiskScore}/100";
        DetailCategory.Text = f.Category;
        DetailPath.Text = string.IsNullOrWhiteSpace(f.Path) ? "—" : f.Path;
        DetailSignature.Text = f.Signature;
        DetailHash.Text = string.IsNullOrWhiteSpace(f.Sha256) ? "Не вычислен" : f.Sha256;
        DetailReason.Text = f.Reason;
        DetailDate.Text = f.LastDetectedDisplay;
        DetailEvidencesList.ItemsSource = f.Evidences;
        OpenFolderBtn.IsEnabled = !string.IsNullOrWhiteSpace(f.Path) && (File.Exists(f.Path) || Directory.Exists(f.Path));

        DetailColumn.Width = new GridLength(360);
        DetailPanel.Opacity = 0;
        DetailPanel.BeginAnimation(OpacityProperty,
            new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            });
    }

    void CloseDetails_Click(object sender, RoutedEventArgs e) => DetailColumn.Width = new GridLength(0);

    void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(selectedPath)) return;
        try
        {
            if (File.Exists(selectedPath))
                Process.Start("explorer.exe", $"/select,\"{selectedPath}\"");
            else if (Directory.Exists(selectedPath))
                Process.Start("explorer.exe", $"\"{selectedPath}\"");
        }
        catch { }
    }

    async void ExportHtml_Click(object sender, RoutedEventArgs e)
    {
        if (latest == null) return;
        try
        {
            Directory.CreateDirectory(settings.ReportDirectory);
            string path = System.IO.Path.Combine(settings.ReportDirectory, $"RSS-Scan-{DateTime.Now:yyyyMMdd-HHmmss}.html");
            await ReportExport.HtmlAsync(latest, path);
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "RSS", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    async Task RefreshHistoryAsync()
    {
        var h = await store.LoadHistoryAsync();
        HistoryList.ItemsSource = h;
        HistoryEmpty.Visibility = h.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        latest ??= h.FirstOrDefault();
        await RefreshOverviewAsync();
    }

    async Task RefreshOverviewAsync()
    {
        var h = await store.LoadHistoryAsync();
        var r = latest ?? h.FirstOrDefault();
        if (r == null)
        {
            ObjectsValue.Text = "—";
            ConfirmedValue.Text = "0";
            ReviewValue.Text = "0";
            return;
        }

        ObjectsValue.Text = r.ObjectsChecked.ToString("N0");
        ConfirmedValue.Text = r.Findings.Count(x => x.Status is DetectionStatus.CheatDetected or DetectionStatus.HighRisk).ToString();
        ReviewValue.Text = r.Findings.Count(x => x.Status == DetectionStatus.Suspicious).ToString();
        LastScanText.Text = isRussian
            ? $"Последняя проверка: {r.FinishedAt:g} · {r.Mode}"
            : $"Last scan: {r.FinishedAt:g} · {r.Mode}";
    }

    void UpdateEmptyState()
    {
        if (ResultsEmpty == null) return;
        int count = resultsView?.Cast<object>().Count() ?? 0;
        ResultCount.Text = isRussian ? $"Найдено: {count}" : $"{count} result(s)";
        ResultsEmpty.Visibility = count > 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    async void Lang_Click(object sender, RoutedEventArgs e)
    {
        isRussian = !isRussian;
        settings.Language = isRussian ? "Русский" : "English";
        ApplyLanguage();
        await RefreshOverviewAsync();
        await store.SaveSettingsAsync(settings);
    }

    void ApplyLanguage()
    {
        LangBtn.Content = isRussian ? "RU" : "EN";

        NavScanBtn.Content = isRussian ? "Сканирование" : "Scan";
        NavResultsBtn.Content = isRussian ? "Результаты" : "Results";
        NavHistoryBtn.Content = isRussian ? "История" : "History";

        if (!scanning)
        {
            ProtectionText.Text = isRussian ? "Готово к проверке" : "Ready to scan";
            if (latest == null)
                LastScanText.Text = isRussian ? "Выберите режим и нажмите кнопку ниже" : "Choose a mode and click below to start";
            PhaseText.Text = isRussian ? "Ожидание запуска" : "Ready";
            ScanActionBtn.Content = isRussian ? "Начать проверку" : "Start scan";
        }

        QuickTitle.Text = isRussian ? "⚡  Быстрая проверка" : "⚡  Quick Scan";
        QuickTimeText.Text = isRussian ? "~15 сек" : "~15 sec";
        QuickDesc.Text = isRussian
            ? "Проверяет активные программы, основные папки и автозагрузку."
            : "Checks running apps, common folders, and startup items.";

        FullTitle.Text = isRussian ? "🔍  Полная проверка" : "🔍  Full Scan";
        FullTimeText.Text = isRussian ? "~1–2 мин" : "~1–2 min";
        FullDesc.Text = isRussian
            ? "Глубокая проверка всех разделов, файлов и системных следов."
            : "Deep check across files, system locations, and artifacts.";

        ViewResultsBtn.Content = isRussian ? "Открыть результаты" : "View results";

        StatCheckedLabel.Text = isRussian ? "ПРОВЕРЕНО" : "CHECKED";
        StatCheckedSub.Text = isRussian ? "объектов в системе" : "objects scanned";
        StatConfirmedLabel.Text = isRussian ? "НАЙДЕНО УГРОЗ" : "THREATS";
        StatConfirmedSub.Text = isRussian ? "подтверждённые совпадения" : "confirmed matches";
        StatReviewLabel.Text = isRussian ? "ТРЕБУЕТ ВНИМАНИЯ" : "NEEDS REVIEW";
        StatReviewSub.Text = isRussian ? "подозрительные объекты" : "suspicious items";

        ResultsTitle.Text = isRussian ? "Результаты проверки" : "Scan Results";
        ResultsSubtitle.Text = isRussian ? "Нажмите на строку, чтобы посмотреть подробности." : "Click any item to view details.";
        ExportHtmlBtn.Content = isRussian ? "Сохранить отчёт" : "Save report";
        ResultsEmpty.Text = isRussian
            ? "Пока нет результатов. Запустите проверку на главном экране."
            : "No results yet. Run a scan from the home screen.";

        if (StatusFilter.Items[0] is ComboBoxItem allItem)
            allItem.Content = isRussian ? "Все статусы" : "All statuses";

        ResultsGrid.Columns[0].Header = isRussian ? "Статус" : "Status";
        ResultsGrid.Columns[1].Header = isRussian ? "Риск" : "Risk";
        ResultsGrid.Columns[2].Header = isRussian ? "Название" : "Name";
        ResultsGrid.Columns[3].Header = isRussian ? "Подпись" : "Signature";
        ResultsGrid.Columns[4].Header = isRussian ? "Путь" : "Path";

        DetailHeader.Text = isRussian ? "Подробности" : "Details";
        DetailPathLabel.Text = isRussian ? "ПУТЬ" : "PATH";
        DetailReasonLabel.Text = isRussian ? "ПОЧЕМУ ЭТО ОТМЕЧЕНО" : "REASON";
        OpenFolderBtn.Content = isRussian ? "Открыть в проводнике" : "Open in Explorer";

        HistoryTitle.Text = isRussian ? "История проверок" : "Scan History";
        HistorySubtitle.Text = isRussian ? "Недавние проверки на этом устройстве." : "Recent scans on this device.";
        HistoryEmpty.Text = isRussian ? "Пока нет сохранённых проверок." : "No saved scans yet.";

        UpdateEmptyState();
    }

    #endregion
}
