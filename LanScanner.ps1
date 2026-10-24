param(
    [string]$Target = "",
    [switch]$AutoStart,
    [switch]$Demo
)

$ErrorActionPreference = 'Stop'
$script:AppDir = $PSScriptRoot

# ---------------------------------------------------------------------------
# Native scan engine (parallel ARP + ICMP probe, thread-safe result queue)
# ---------------------------------------------------------------------------
$scanEngineSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

public class LanScanResult
{
    public string IP { get; set; }
    public bool Alive { get; set; }
    public long PingMs { get; set; }
    public string Mac { get; set; }
    public string HostName { get; set; }
    public string Method { get; set; }
}

public class LanScanEngine
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint phyAddrLen);

    private readonly ConcurrentQueue<LanScanResult> _queue = new ConcurrentQueue<LanScanResult>();
    private readonly List<uint[]> _localNets = new List<uint[]>();
    private readonly Dictionary<uint, string> _localMacs = new Dictionary<uint, string>();
    private int _total;
    private int _completed;
    private int _nextIndex;
    private volatile bool _complete;
    private volatile bool _cancel;

    public int Total { get { return _total; } }
    public int Completed { get { return Volatile.Read(ref _completed); } }
    public int Pending { get { return _queue.Count; } }
    public bool IsComplete { get { return _complete; } }
    public bool IsCancelled { get { return _cancel; } }

    public void Cancel()
    {
        _cancel = true;
    }

    public LanScanResult Next()
    {
        LanScanResult result;
        if (_queue.TryDequeue(out result)) return result;
        return null;
    }

    public void Start(string[] ips, int timeoutMs, int concurrency)
    {
        _total = ips.Length;
        _completed = 0;
        _nextIndex = -1;
        _complete = false;
        _cancel = false;
        LoadLocalAddresses();

        Thread starter = new Thread(new ThreadStart(delegate { Run(ips, timeoutMs, concurrency); }));
        starter.IsBackground = true;
        starter.Start();
    }

    private void Run(string[] ips, int timeoutMs, int concurrency)
    {
        try
        {
            int workerCount = concurrency;
            if (workerCount > ips.Length) workerCount = ips.Length;
            if (workerCount < 1) workerCount = 1;

            Thread[] workers = new Thread[workerCount];
            for (int i = 0; i < workerCount; i++)
            {
                workers[i] = new Thread(new ThreadStart(delegate()
                {
                    while (!_cancel)
                    {
                        int index = Interlocked.Increment(ref _nextIndex);
                        if (index >= ips.Length) break;

                        string ip = ips[index];
                        LanScanResult result;
                        try
                        {
                            result = ScanOne(ip, timeoutMs);
                        }
                        catch
                        {
                            result = new LanScanResult();
                            result.IP = ip;
                            result.Alive = false;
                            result.PingMs = -1;
                            result.Mac = "";
                            result.HostName = "";
                            result.Method = "";
                        }

                        _queue.Enqueue(result);
                        Interlocked.Increment(ref _completed);
                    }
                }));
                workers[i].IsBackground = true;
                workers[i].Start();
            }

            for (int i = 0; i < workers.Length; i++)
            {
                workers[i].Join();
            }
        }
        finally
        {
            _complete = true;
        }
    }

    private LanScanResult ScanOne(string ip, int timeoutMs)
    {
        LanScanResult result = new LanScanResult();
        result.IP = ip;
        result.Mac = "";
        result.HostName = "";
        result.PingMs = -1;
        result.Method = "";

        IPAddress address = IPAddress.Parse(ip);
        uint ipValue = ToUInt32(address.GetAddressBytes());

        if (_localMacs.ContainsKey(ipValue))
        {
            result.Alive = true;
            result.Method = "本机";
            result.Mac = _localMacs[ipValue];
            result.PingMs = 0;
            result.HostName = SafeLocalHostName();
            return result;
        }

        string mac = TryArp(ip, ipValue);
        if (mac != null)
        {
            result.Alive = true;
            result.Method = "ARP";
            result.Mac = mac;
            result.PingMs = 0;
            result.HostName = TryReverseDns(ip, 280);
            return result;
        }

        try
        {
            using (Ping ping = new Ping())
            {
                PingReply reply = ping.Send(address, timeoutMs);
                if (reply != null && reply.Status == IPStatus.Success)
                {
                    result.Alive = true;
                    result.Method = "ICMP";
                    result.PingMs = reply.RoundtripTime;
                }
            }
        }
        catch
        {
        }

        if (result.Alive)
        {
            result.HostName = TryReverseDns(ip, 280);
        }

        return result;
    }

    private string TryArp(string ip, uint ipValue)
    {
        if (!IsLocalAddress(ipValue)) return null;

        try
        {
            byte[] macBytes = new byte[6];
            uint length = (uint)macBytes.Length;
            uint dest = BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0);
            int code = SendARP(dest, 0, macBytes, ref length);
            if (code == 0 && length >= 6)
            {
                bool allZero = true;
                for (int i = 0; i < 6; i++)
                {
                    if (macBytes[i] != 0) { allZero = false; break; }
                }
                if (!allZero)
                {
                    return string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}",
                        macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5]);
                }
            }
        }
        catch
        {
        }
        return null;
    }

    private bool IsLocalAddress(uint ip)
    {
        for (int i = 0; i < _localNets.Count; i++)
        {
            uint[] item = _localNets[i];
            if ((ip & item[1]) == item[0]) return true;
        }
        return false;
    }

    private void LoadLocalAddresses()
    {
        _localNets.Clear();
        _localMacs.Clear();

        try
        {
            NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface ni in interfaces)
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (ni.OperationalStatus != OperationalStatus.Up) continue;

                IPInterfaceProperties props;
                try { props = ni.GetIPProperties(); }
                catch { continue; }

                string mac = "";
                try
                {
                    PhysicalAddress pa = ni.GetPhysicalAddress();
                    if (pa != null) mac = FormatMac(pa.GetAddressBytes());
                }
                catch { }

                foreach (UnicastIPAddressInformation ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                    byte[] bytes = ua.Address.GetAddressBytes();
                    uint ip = ToUInt32(bytes);
                    int prefix = 24;
                    try { prefix = ua.PrefixLength; }
                    catch { }

                    if (prefix < 0 || prefix > 32) prefix = 24;
                    uint mask = prefix == 0 ? 0 : (uint)(0xFFFFFFFFu << (32 - prefix));
                    _localNets.Add(new uint[] { ip & mask, mask });
                    if (mac.Length > 0) _localMacs[ip] = mac;
                }
            }
        }
        catch
        {
        }
    }

    private static string FormatMac(byte[] bytes)
    {
        if (bytes == null || bytes.Length < 6) return "";
        return string.Format("{0:X2}-{1:X2}-{2:X2}-{3:X2}-{4:X2}-{5:X2}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    }

    private static uint ToUInt32(byte[] bytes)
    {
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static string SafeLocalHostName()
    {
        try { return Dns.GetHostName(); }
        catch { return ""; }
    }

    private static string TryReverseDns(string ip, int timeoutMs)
    {
        try
        {
            IAsyncResult ar = Dns.BeginGetHostEntry(IPAddress.Parse(ip), null, null);
            if (ar.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                IPHostEntry entry = Dns.EndGetHostEntry(ar);
                if (entry != null && entry.HostName != null) return entry.HostName;
            }
        }
        catch
        {
        }
        return "";
    }
}
'@

Add-Type -TypeDefinition $scanEngineSource -Language CSharp

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# ---------------------------------------------------------------------------
# UI definition
# ---------------------------------------------------------------------------
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework"
        Title="网段占用扫描"
        Width="1180" Height="720" MinWidth="980" MinHeight="620"
        WindowStartupLocation="CenterScreen"
        WindowStyle="None" AllowsTransparency="False"
        Background="#0A1120"
        FontFamily="Microsoft YaHei UI"
        TextOptions.TextFormattingMode="Display"
        UseLayoutRounding="True" SnapsToDevicePixels="True">

    <shell:WindowChrome.WindowChrome>
        <shell:WindowChrome CaptionHeight="0" ResizeBorderThickness="6"
                            GlassFrameThickness="0" CornerRadius="0"
                            UseAeroCaptionButtons="False"/>
    </shell:WindowChrome.WindowChrome>

    <Window.Resources>
        <SolidColorBrush x:Key="Accent" Color="#38BDF8"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#E8F0FC"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#8297B6"/>
        <SolidColorBrush x:Key="TextMuted" Color="#526987"/>
        <SolidColorBrush x:Key="Red" Color="#FF5D73"/>
        <SolidColorBrush x:Key="Green" Color="#34D399"/>

        <Style x:Key="Card" TargetType="Border">
            <Setter Property="Background" Value="#101B2E"/>
            <Setter Property="BorderBrush" Value="#1D2C48"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="12"/>
        </Style>

        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Height" Value="42"/>
            <Setter Property="Padding" Value="20,0"/>
            <Setter Property="Background" Value="#38BDF8"/>
            <Setter Property="Foreground" Value="#04111F"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}"
                                CornerRadius="8" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#5FCBFA"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#1FA9E2"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#1A2A42"/>
                                <Setter Property="Foreground" Value="#607492"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Height" Value="42"/>
            <Setter Property="Padding" Value="16,0"/>
            <Setter Property="Background" Value="#132139"/>
            <Setter Property="Foreground" Value="#B9C9DF"/>
            <Setter Property="BorderBrush" Value="#263A5B"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="8" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#1A2C48"/>
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#375277"/>
                                <Setter Property="Foreground" Value="#E8F0FC"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#0F1B2F"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#4F6482"/>
                                <Setter TargetName="Bd" Property="Background" Value="#0F1929"/>
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#1B2A42"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="StopButton" TargetType="Button" BasedOn="{StaticResource SecondaryButton}">
            <Setter Property="Foreground" Value="#FFAFBA"/>
            <Setter Property="BorderBrush" Value="#522B39"/>
            <Setter Property="Background" Value="#20131D"/>
        </Style>

        <Style x:Key="CaptionButton" TargetType="Button">
            <Setter Property="Width" Value="42"/>
            <Setter Property="Height" Value="30"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#7F93B2"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
            <Setter Property="FontSize" Value="10"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="Transparent" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#182740"/>
                                <Setter Property="Foreground" Value="#E8F0FC"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="CloseButton" TargetType="Button" BasedOn="{StaticResource CaptionButton}">
            <Setter Property="Foreground" Value="#C98691"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="Bd" Background="Transparent" CornerRadius="6">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#E81123"/>
                                <Setter Property="Foreground" Value="#FFFFFF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="InputBox" TargetType="TextBox">
            <Setter Property="Height" Value="42"/>
            <Setter Property="Background" Value="#0B1628"/>
            <Setter Property="Foreground" Value="#E8F0FC"/>
            <Setter Property="CaretBrush" Value="#38BDF8"/>
            <Setter Property="BorderBrush" Value="#233553"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="13,0"/>
            <Setter Property="FontFamily" Value="Consolas, Microsoft YaHei UI"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="SelectionBrush" Value="#2B7FB0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="Bd" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="8" SnapsToDevicePixels="True">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}"
                                          VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#35517B"/>
                            </Trigger>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="#38BDF8"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="Segment" TargetType="RadioButton">
            <Setter Property="Foreground" Value="#7388A7"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Padding" Value="13,5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="RadioButton">
                        <Border x:Name="Bd" Background="Transparent" CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#15243B"/>
                                <Setter Property="Foreground" Value="#B7C7DE"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#1D304D"/>
                                <Setter Property="Foreground" Value="#E8F0FC"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ScanProgress" TargetType="ProgressBar">
            <Setter Property="Height" Value="6"/>
            <Setter Property="Background" Value="#1A2942"/>
            <Setter Property="Foreground" Value="#38BDF8"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Grid>
                            <Border x:Name="PART_Track" Background="{TemplateBinding Background}"
                                    CornerRadius="3"/>
                            <Border x:Name="PART_Indicator" HorizontalAlignment="Left"
                                    Background="{TemplateBinding Foreground}" CornerRadius="3"/>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="ScrollThumb" TargetType="Thumb">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Thumb">
                        <Border x:Name="Bd" Background="#2A3F5F" CornerRadius="3"/>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#3A577F"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="ScrollBar">
            <Setter Property="Width" Value="8"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ScrollBar">
                        <Grid Background="Transparent" Margin="2,0">
                            <Track x:Name="PART_Track" IsDirectionReversed="True">
                                <Track.DecreaseRepeatButton>
                                    <RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/>
                                </Track.DecreaseRepeatButton>
                                <Track.Thumb>
                                    <Thumb Style="{StaticResource ScrollThumb}"/>
                                </Track.Thumb>
                                <Track.IncreaseRepeatButton>
                                    <RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/>
                                </Track.IncreaseRepeatButton>
                            </Track>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Height" Value="40"/>
            <Setter Property="Background" Value="#0D1729"/>
            <Setter Property="Foreground" Value="#6F84A4"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="14,0"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridColumnHeader">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="#1A2942" BorderThickness="0,0,0,1"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="14,0"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="Transparent" Padding="{TemplateBinding Padding}"
                                SnapsToDevicePixels="True">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#C4D2E7"/>
            <Setter Property="Height" Value="46"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#14243C"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#1A3150"/>
                </Trigger>
                <DataTrigger Binding="{Binding Occupied}" Value="True">
                    <Setter Property="Background" Value="#24FF5D73"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="ResultGrid" TargetType="DataGrid">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Foreground" Value="#C4D2E7"/>
            <Setter Property="RowBackground" Value="Transparent"/>
            <Setter Property="GridLinesVisibility" Value="None"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="AutoGenerateColumns" Value="False"/>
            <Setter Property="CanUserAddRows" Value="False"/>
            <Setter Property="CanUserDeleteRows" Value="False"/>
            <Setter Property="CanUserResizeRows" Value="False"/>
            <Setter Property="CanUserReorderColumns" Value="False"/>
            <Setter Property="CanUserResizeColumns" Value="False"/>
            <Setter Property="CanUserSortColumns" Value="False"/>
            <Setter Property="SelectionMode" Value="Single"/>
            <Setter Property="SelectionUnit" Value="FullRow"/>
            <Setter Property="IsReadOnly" Value="True"/>
            <Setter Property="ColumnHeaderHeight" Value="40"/>
            <Setter Property="RowHeight" Value="46"/>
            <Setter Property="HorizontalGridLinesBrush" Value="Transparent"/>
            <Setter Property="VerticalGridLinesBrush" Value="Transparent"/>
            <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
            <Setter Property="ScrollViewer.VerticalScrollBarVisibility" Value="Auto"/>
            <Setter Property="EnableRowVirtualization" Value="True"/>
        </Style>

        <Style TargetType="ToolTip">
            <Setter Property="Background" Value="#16243A"/>
            <Setter Property="Foreground" Value="#D7E3F5"/>
            <Setter Property="BorderBrush" Value="#2A3E5E"/>
            <Setter Property="FontSize" Value="12"/>
        </Style>
    </Window.Resources>

    <Border BorderBrush="#23324F" BorderThickness="1" Background="#0A1120">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="2"/>
                <RowDefinition Height="60"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>

            <Border Grid.Row="0">
                <Border.Background>
                    <LinearGradientBrush StartPoint="0,0" EndPoint="1,0">
                        <GradientStop Color="#0A1120" Offset="0"/>
                        <GradientStop Color="#38BDF8" Offset="0.28"/>
                        <GradientStop Color="#6366F1" Offset="0.62"/>
                        <GradientStop Color="#0A1120" Offset="1"/>
                    </LinearGradientBrush>
                </Border.Background>
            </Border>

            <Grid Grid.Row="1" Background="#0C1525">
                <Border BorderBrush="#17243B" BorderThickness="0,0,0,1"/>

                <Grid x:Name="titleDrag" Background="Transparent" Margin="22,0,0,0">
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <Border Width="34" Height="34" CornerRadius="10" Background="#12314A"
                                BorderBrush="#2B6688" BorderThickness="1">
                            <TextBlock Text="IP" Foreground="#57D3FA" FontSize="13" FontWeight="Bold"
                                       FontFamily="Segoe UI" HorizontalAlignment="Center"
                                       VerticalAlignment="Center"/>
                        </Border>
                        <StackPanel Margin="12,0,0,0" VerticalAlignment="Center">
                            <StackPanel Orientation="Horizontal">
                                <TextBlock Text="网段占用扫描" Foreground="#E8F0FC" FontSize="15"
                                           FontWeight="SemiBold" VerticalAlignment="Center"/>
                                <Border Background="#12233A" CornerRadius="5" Padding="7,2"
                                        Margin="10,0,0,0" VerticalAlignment="Center">
                                    <TextBlock Text="LAN SCANNER" Foreground="#4E87AE" FontSize="8"
                                               FontFamily="Segoe UI" FontWeight="SemiBold"/>
                                </Border>
                            </StackPanel>
                            <TextBlock Text="局域网设备发现与占用检测" Foreground="#5E7392"
                                       FontSize="10" Margin="0,2,0,0"/>
                        </StackPanel>
                    </StackPanel>
                </Grid>

                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
                            VerticalAlignment="Center" Margin="0,0,12,0">
                    <Button x:Name="btnMin" Content="&#xE921;" Style="{StaticResource CaptionButton}"
                            ToolTip="最小化"/>
                    <Button x:Name="btnMax" Content="&#xE922;" Style="{StaticResource CaptionButton}"
                            ToolTip="最大化"/>
                    <Button x:Name="btnClose" Content="&#xE8BB;" Style="{StaticResource CloseButton}"
                            ToolTip="关闭"/>
                </StackPanel>
            </Grid>

            <Grid Grid.Row="2" Margin="26,20,26,16">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <Border Grid.Row="0" Style="{StaticResource Card}" Padding="22,17,22,15">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Grid Grid.Row="0">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>

                            <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="扫描网段" Foreground="#DCE7F7" FontSize="13"
                                           FontWeight="SemiBold"/>
                                <TextBlock Text="CIDR / IP 范围" Foreground="#5A7090" FontSize="10"
                                           Margin="0,2,0,0"/>
                            </StackPanel>

                            <TextBox x:Name="txtTarget" Grid.Column="1" Width="350" Margin="16,0,0,0"
                                     Style="{StaticResource InputBox}" FontSize="14"
                                     ToolTip="例如：192.168.1.0/24、192.168.1.1-254、192.168.1.88"/>
                            <StackPanel Grid.Column="2" Orientation="Horizontal"
                                        Margin="10,0,0,0" VerticalAlignment="Center">
                                <Button x:Name="btnScan" Style="{StaticResource PrimaryButton}">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="&#xE768;" FontFamily="Segoe MDL2 Assets" FontSize="10"
                                                   Margin="0,1,8,0" VerticalAlignment="Center"/>
                                        <TextBlock x:Name="txtScanBtn" Text="开始扫描" FontWeight="SemiBold"/>
                                    </StackPanel>
                                </Button>
                                <Button x:Name="btnStop" Width="86" Visibility="Collapsed"
                                        Style="{StaticResource StopButton}">
                                    <StackPanel Orientation="Horizontal">
                                        <TextBlock Text="&#xE71A;" FontFamily="Segoe MDL2 Assets" FontSize="10"
                                                   Margin="0,1,7,0" VerticalAlignment="Center"/>
                                        <TextBlock Text="停止" FontWeight="SemiBold"/>
                                    </StackPanel>
                                </Button>
                                <Button x:Name="btnLocal" Width="104" Margin="8,0,0,0"
                                        Content="本机网段" Style="{StaticResource SecondaryButton}"/>
                            </StackPanel>
                        </Grid>

                        <Grid Grid.Row="1" Margin="0,15,0,0">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <ProgressBar x:Name="barProgress" Style="{StaticResource ScanProgress}"
                                         Minimum="0" Maximum="100" Value="0"/>
                            <TextBlock x:Name="lblPercent" Grid.Column="1" Text="0%" Width="46"
                                       TextAlignment="Right" Foreground="#607795" FontSize="11"
                                       FontFamily="Segoe UI" VerticalAlignment="Center"/>
                        </Grid>
                    </Grid>
                </Border>

                <Grid Grid.Row="1" Margin="0,14,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <Border Grid.Column="0" Style="{StaticResource Card}" Padding="18,13" Margin="0,0,7,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="已扫描 / 总数" Foreground="#7086A6" FontSize="11"/>
                                <TextBlock x:Name="lblScanned" Text="0 / 0" Foreground="#E8F0FC"
                                           FontFamily="Segoe UI" FontSize="23" FontWeight="SemiBold"
                                           Margin="0,4,0,0"/>
                            </StackPanel>
                            <Border Grid.Column="1" Width="36" Height="36" CornerRadius="10"
                                    Background="#142943" VerticalAlignment="Center">
                                <TextBlock Text="&#xE968;" FontFamily="Segoe MDL2 Assets" FontSize="15"
                                           Foreground="#4DBDEB" HorizontalAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                    </Border>

                    <Border Grid.Column="1" Style="{StaticResource Card}" Padding="18,13" Margin="7,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="占用主机" Foreground="#7086A6" FontSize="11"/>
                                <StackPanel Orientation="Horizontal" Margin="0,2,0,0">
                                    <TextBlock x:Name="lblOccupied" Text="0" Foreground="#FF6B7E"
                                               FontFamily="Segoe UI" FontSize="25" FontWeight="Bold"/>
                                    <TextBlock Text="台" Foreground="#8A6070" FontSize="11"
                                               Margin="5,9,0,0"/>
                                </StackPanel>
                            </StackPanel>
                            <Border Grid.Column="1" Width="36" Height="36" CornerRadius="10"
                                    Background="#281820" VerticalAlignment="Center">
                                <TextBlock Text="&#xE783;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                           Foreground="#FF6B7E" HorizontalAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                    </Border>

                    <Border Grid.Column="2" Style="{StaticResource Card}" Padding="18,13" Margin="7,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="未占用" Foreground="#7086A6" FontSize="11"/>
                                <StackPanel Orientation="Horizontal" Margin="0,2,0,0">
                                    <TextBlock x:Name="lblFree" Text="0" Foreground="#4DDFA8"
                                               FontFamily="Segoe UI" FontSize="25" FontWeight="Bold"/>
                                    <TextBlock Text="个" Foreground="#4D7C6D" FontSize="11"
                                               Margin="5,9,0,0"/>
                                </StackPanel>
                            </StackPanel>
                            <Border Grid.Column="1" Width="36" Height="36" CornerRadius="10"
                                    Background="#122820" VerticalAlignment="Center">
                                <TextBlock Text="&#xE73E;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                           Foreground="#34D399" HorizontalAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                    </Border>

                    <Border Grid.Column="3" Style="{StaticResource Card}" Padding="18,13" Margin="7,0,0,0">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel VerticalAlignment="Center">
                                <TextBlock Text="扫描耗时" Foreground="#7086A6" FontSize="11"/>
                                <TextBlock x:Name="lblElapsed" Text="--" Foreground="#D8E5F7"
                                           FontFamily="Segoe UI" FontSize="23" FontWeight="SemiBold"
                                           Margin="0,4,0,0"/>
                            </StackPanel>
                            <Border Grid.Column="1" Width="36" Height="36" CornerRadius="10"
                                    Background="#17203A" VerticalAlignment="Center">
                                <TextBlock Text="&#xE823;" FontFamily="Segoe MDL2 Assets" FontSize="14"
                                           Foreground="#8496F4" HorizontalAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Border>
                        </Grid>
                    </Border>
                </Grid>

                <Grid Grid.Row="2" Margin="0,17,0,10">
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock Text="扫描结果" Foreground="#DCE7F7" FontSize="14"
                                   FontWeight="SemiBold" VerticalAlignment="Center"/>
                        <Border Background="#12233A" CornerRadius="7" Padding="8,2"
                                Margin="9,0,0,0" VerticalAlignment="Center">
                            <TextBlock x:Name="lblResultCount" Text="0 个结果" Foreground="#6F86A8"
                                       FontSize="10" FontFamily="Segoe UI"/>
                        </Border>
                    </StackPanel>

                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
                                VerticalAlignment="Center">
                        <Border Width="224" Height="34" Background="#0C1627" BorderBrush="#1E2C48"
                                BorderThickness="1" CornerRadius="8">
                            <Grid>
                                <TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="12"
                                           Foreground="#5D7292" Margin="11,0,0,0"
                                           HorizontalAlignment="Left" VerticalAlignment="Center"/>
                                <TextBlock x:Name="txtSearchHint" Text="搜索 IP / MAC / 主机名"
                                           Foreground="#415672" FontSize="11" Margin="31,0,0,0"
                                           HorizontalAlignment="Left" VerticalAlignment="Center"
                                           IsHitTestVisible="False"/>
                                <TextBox x:Name="txtSearch" Background="Transparent" BorderThickness="0"
                                         Foreground="#D8E5F7" CaretBrush="#38BDF8" FontSize="12"
                                         Padding="30,0,8,0" VerticalContentAlignment="Center">
                                    <TextBox.Template>
                                        <ControlTemplate TargetType="TextBox">
                                            <ScrollViewer x:Name="PART_ContentHost"
                                                          Margin="{TemplateBinding Padding}"
                                                          VerticalAlignment="Center"/>
                                        </ControlTemplate>
                                    </TextBox.Template>
                                </TextBox>
                            </Grid>
                        </Border>

                        <Border Background="#0C1627" BorderBrush="#1E2C48" BorderThickness="1"
                                CornerRadius="9" Padding="3" Margin="10,0,0,0">
                            <StackPanel Orientation="Horizontal">
                                <RadioButton x:Name="rbAll" Content="全部" GroupName="ResultFilter"
                                             IsChecked="True" Style="{StaticResource Segment}"/>
                                <RadioButton x:Name="rbOccupied" Content="占用" GroupName="ResultFilter"
                                             Style="{StaticResource Segment}"/>
                                <RadioButton x:Name="rbFree" Content="未占用" GroupName="ResultFilter"
                                             Style="{StaticResource Segment}"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </Grid>

                <Border Grid.Row="3" Style="{StaticResource Card}" CornerRadius="12"
                        ClipToBounds="True">
                    <Grid>
                        <DataGrid x:Name="gridResults" Style="{StaticResource ResultGrid}" Margin="1,1,1,1">
                            <DataGrid.Columns>
                                <DataGridTemplateColumn Header="状态" Width="96">
                                    <DataGridTemplateColumn.CellTemplate>
                                        <DataTemplate>
                                            <Border x:Name="pill" Background="#14263E" CornerRadius="9"
                                                    Padding="9,4" HorizontalAlignment="Left">
                                                <StackPanel Orientation="Horizontal">
                                                    <Ellipse x:Name="dot" Width="6" Height="6"
                                                             Fill="#34D399" Margin="0,0,6,0"
                                                             VerticalAlignment="Center"/>
                                                    <TextBlock x:Name="statusText" Text="{Binding State}"
                                                               Foreground="#9CB0CC" FontSize="11"/>
                                                </StackPanel>
                                            </Border>
                                            <DataTemplate.Triggers>
                                                <DataTrigger Binding="{Binding Occupied}" Value="True">
                                                    <Setter TargetName="pill" Property="Background" Value="#30FF5D73"/>
                                                    <Setter TargetName="dot" Property="Fill" Value="#FF5D73"/>
                                                    <Setter TargetName="statusText" Property="Foreground" Value="#FFAFB9"/>
                                                </DataTrigger>
                                            </DataTemplate.Triggers>
                                        </DataTemplate>
                                    </DataGridTemplateColumn.CellTemplate>
                                </DataGridTemplateColumn>

                                <DataGridTemplateColumn Header="IP 地址" Width="170">
                                    <DataGridTemplateColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding IP}" FontFamily="Consolas"
                                                       FontSize="13" FontWeight="SemiBold">
                                                <TextBlock.Style>
                                                    <Style TargetType="TextBlock">
                                                        <Setter Property="Foreground" Value="#CFDCF0"/>
                                                        <Style.Triggers>
                                                            <DataTrigger Binding="{Binding Occupied}" Value="True">
                                                                <Setter Property="Foreground" Value="#FF6B7E"/>
                                                            </DataTrigger>
                                                        </Style.Triggers>
                                                    </Style>
                                                </TextBlock.Style>
                                            </TextBlock>
                                        </DataTemplate>
                                    </DataGridTemplateColumn.CellTemplate>
                                </DataGridTemplateColumn>

                                <DataGridTemplateColumn Header="延迟" Width="105">
                                    <DataGridTemplateColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding Latency}" FontFamily="Segoe UI"
                                                       FontSize="12">
                                                <TextBlock.Style>
                                                    <Style TargetType="TextBlock">
                                                        <Setter Property="Foreground" Value="#8498B6"/>
                                                        <Style.Triggers>
                                                            <DataTrigger Binding="{Binding Occupied}" Value="True">
                                                                <Setter Property="Foreground" Value="#D9929C"/>
                                                            </DataTrigger>
                                                        </Style.Triggers>
                                                    </Style>
                                                </TextBlock.Style>
                                            </TextBlock>
                                        </DataTemplate>
                                    </DataGridTemplateColumn.CellTemplate>
                                </DataGridTemplateColumn>

                                <DataGridTemplateColumn Header="主机名" Width="*">
                                    <DataGridTemplateColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding HostName}" Foreground="#AABBD3"
                                                       FontSize="12" TextTrimming="CharacterEllipsis"
                                                       ToolTip="{Binding HostName}"/>
                                        </DataTemplate>
                                    </DataGridTemplateColumn.CellTemplate>
                                </DataGridTemplateColumn>

                                <DataGridTemplateColumn Header="MAC 地址" Width="185">
                                    <DataGridTemplateColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding Mac}" FontFamily="Consolas"
                                                       FontSize="11" Foreground="#7F94B3"/>
                                        </DataTemplate>
                                    </DataGridTemplateColumn.CellTemplate>
                                </DataGridTemplateColumn>
                            </DataGrid.Columns>
                        </DataGrid>

                        <StackPanel x:Name="emptyState" HorizontalAlignment="Center"
                                    VerticalAlignment="Center" IsHitTestVisible="False">
                            <Border Width="58" Height="58" CornerRadius="18" Background="#101F34"
                                    BorderBrush="#1E3552" BorderThickness="1" HorizontalAlignment="Center">
                                <TextBlock Text="&#xE968;" FontFamily="Segoe MDL2 Assets" FontSize="24"
                                           Foreground="#3D6C8E" HorizontalAlignment="Center"
                                           VerticalAlignment="Center"/>
                            </Border>
                            <TextBlock x:Name="lblEmptyTitle" Text="还没有扫描结果"
                                       Foreground="#A9BCD5" FontSize="14" FontWeight="SemiBold"
                                       HorizontalAlignment="Center" Margin="0,14,0,0"/>
                            <TextBlock x:Name="lblEmptyDesc" Text="输入网段后点击“开始扫描”"
                                       Foreground="#566B89" FontSize="11"
                                       HorizontalAlignment="Center" Margin="0,5,0,0"/>
                        </StackPanel>
                    </Grid>
                </Border>

                <Grid Grid.Row="4" Margin="0,11,0,0">
                    <TextBlock x:Name="lblStatus" Text="就绪" Foreground="#667D9D" FontSize="10"
                               VerticalAlignment="Center"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
                                VerticalAlignment="Center">
                        <Ellipse Width="6" Height="6" Fill="#FF5D73" VerticalAlignment="Center"/>
                        <TextBlock Text="红色 = 已占用" Foreground="#7086A6" FontSize="10"
                                   Margin="6,0,0,0"/>
                        <Border Width="1" Height="9" Background="#243553" Margin="13,0"/>
                        <TextBlock Text="本机网段使用 ARP + ICMP 探测" Foreground="#526987" FontSize="10"/>
                        <Border Width="1" Height="9" Background="#243553" Margin="13,0"/>
                        <TextBlock Text="跨网段仅 ICMP，可能受防火墙影响" Foreground="#526987" FontSize="10"/>
                    </StackPanel>
                </Grid>
            </Grid>
        </Grid>
    </Border>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------
$txtTarget = $window.FindName('txtTarget')
$btnScan = $window.FindName('btnScan')
$btnStop = $window.FindName('btnStop')
$btnLocal = $window.FindName('btnLocal')
$btnMin = $window.FindName('btnMin')
$btnMax = $window.FindName('btnMax')
$btnClose = $window.FindName('btnClose')
$titleDrag = $window.FindName('titleDrag')
$txtScanBtn = $window.FindName('txtScanBtn')
$barProgress = $window.FindName('barProgress')
$lblPercent = $window.FindName('lblPercent')
$lblScanned = $window.FindName('lblScanned')
$lblOccupied = $window.FindName('lblOccupied')
$lblFree = $window.FindName('lblFree')
$lblElapsed = $window.FindName('lblElapsed')
$lblResultCount = $window.FindName('lblResultCount')
$lblStatus = $window.FindName('lblStatus')
$gridResults = $window.FindName('gridResults')
$emptyState = $window.FindName('emptyState')
$lblEmptyTitle = $window.FindName('lblEmptyTitle')
$lblEmptyDesc = $window.FindName('lblEmptyDesc')
$txtSearch = $window.FindName('txtSearch')
$txtSearchHint = $window.FindName('txtSearchHint')
$rbAll = $window.FindName('rbAll')
$rbOccupied = $window.FindName('rbOccupied')
$rbFree = $window.FindName('rbFree')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
$script:BrushCache = @{}

function Get-UiBrush([string]$hex) {
    if (-not $script:BrushCache.ContainsKey($hex)) {
        $color = [System.Windows.Media.ColorConverter]::ConvertFromString($hex)
        $script:BrushCache[$hex] = New-Object System.Windows.Media.SolidColorBrush($color)
    }
    return $script:BrushCache[$hex]
}

function Convert-IPv4ToNumber([string]$ip) {
    $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [uint64]$value = 0
    foreach ($b in $bytes) {
        $value = ($value * 256) + [uint64]$b
    }
    return $value
}

function Convert-NumberToIPv4([uint64]$value) {
    $bytes = New-Object byte[] 4
    for ($i = 3; $i -ge 0; $i--) {
        $bytes[$i] = [byte]($value -band 255)
        $value = $value -shr 8
    }
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-PrefixMask([int]$prefix) {
    if ($prefix -le 0) { return [uint64]0 }
    return ([uint64]4294967295 -shl (32 - $prefix)) -band [uint64]4294967295
}

function Test-IPv4Address([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    $parts = $text.Split('.')
    if ($parts.Length -ne 4) { return $false }
    foreach ($part in $parts) {
        if ($part -notmatch '^(0|[1-9]\d{0,2})$') { return $false }
        if ([int]$part -gt 255) { return $false }
    }
    return $true
}

function Get-LocalSubnets {
    $items = New-Object System.Collections.ArrayList
    $virtualPattern = 'VMware|VirtualBox|Hyper-V|vEthernet|Loopback|Tailscale|ZeroTier|VPN|TAP|WSL|Docker'

    try {
        $configs = Get-NetIPConfiguration -ErrorAction Stop
        foreach ($config in $configs) {
            if ($null -eq $config.IPv4Address) { continue }
            if ($null -eq $config.NetAdapter) { continue }
            if ($config.NetAdapter.Status -ne 'Up') { continue }

            $ip = $config.IPv4Address.IPAddress
            $prefix = [int]$config.IPv4Address.PrefixLength
            if ($ip -like '169.254.*') { continue }
            if ($ip -like '127.*') { continue }
            if ($prefix -lt 8 -or $prefix -gt 30) { continue }

            $ipValue = Convert-IPv4ToNumber $ip
            $mask = Get-PrefixMask $prefix
            $network = $ipValue -band $mask
            $cidr = "$(Convert-NumberToIPv4 $network)/$prefix"
            $gateway = ''
            if ($null -ne $config.IPv4DefaultGateway) {
                $gateway = ($config.IPv4DefaultGateway | Select-Object -First 1).NextHop
            }
            $alias = [string]$config.InterfaceAlias
            $isVirtual = $alias -match $virtualPattern
            [void]$items.Add([pscustomobject]@{
                CIDR        = $cidr
                Interface   = $alias
                IP          = $ip
                Gateway     = $gateway
                HasGateway  = -not [string]::IsNullOrEmpty($gateway)
                IsVirtual   = [bool]$isVirtual
            })
        }
    }
    catch {
        try {
            $nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
            foreach ($nic in $nics) {
                if ($nic.OperationalStatus -ne 'Up') { continue }
                if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
                foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                    if ($ua.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
                    $ip = $ua.Address.ToString()
                    if ($ip -like '169.254.*' -or $ip -like '127.*') { continue }
                    $prefix = 24
                    try { $prefix = [int]$ua.PrefixLength } catch { }
                    if ($prefix -lt 8 -or $prefix -gt 30) { continue }
                    $network = (Convert-IPv4ToNumber $ip) -band (Get-PrefixMask $prefix)
                    [void]$items.Add([pscustomobject]@{
                        CIDR       = "$(Convert-NumberToIPv4 $network)/$prefix"
                        Interface  = $nic.Name
                        IP         = $ip
                        Gateway    = ''
                        HasGateway = $false
                        IsVirtual  = [bool]($nic.Name -match $virtualPattern)
                    })
                }
            }
        }
        catch {
        }
    }

    $sorted = @($items | Sort-Object `
        @{ Expression = { $_.HasGateway }; Descending = $true }, `
        @{ Expression = { $_.IsVirtual }; Descending = $false }, `
        @{ Expression = { $_.Interface }; Descending = $false })

    $seen = @{}
    $unique = New-Object System.Collections.ArrayList
    foreach ($item in $sorted) {
        if (-not $seen.ContainsKey($item.CIDR)) {
            $seen[$item.CIDR] = $true
            [void]$unique.Add($item)
        }
    }
    return @($unique)
}

function Parse-ScanTarget([string]$text) {
    $raw = $text.Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return [pscustomobject]@{ Ok = $false; Error = '请输入要扫描的网段'; IPs = @() }
    }

    $parts = @($raw -split '[,，;；]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $all = New-Object 'System.Collections.Generic.List[string]'

    foreach ($part in $parts) {
        $start = [uint64]0
        $end = [uint64]0
        $parsed = $false

        if ($part -match '^([^/]+)/(\d{1,2})$') {
            $ipText = $Matches[1].Trim()
            $prefix = [int]$Matches[2]
            if (-not (Test-IPv4Address $ipText)) {
                return [pscustomobject]@{ Ok = $false; Error = "IP 地址无效：$ipText"; IPs = @() }
            }
            if ($prefix -lt 0 -or $prefix -gt 32) {
                return [pscustomobject]@{ Ok = $false; Error = "子网前缀无效：/$prefix"; IPs = @() }
            }
            $ipValue = Convert-IPv4ToNumber $ipText
            $mask = Get-PrefixMask $prefix
            $network = $ipValue -band $mask
            $size = [uint64]1 -shl (32 - $prefix)
            $start = $network
            $end = $network + $size - 1
            if ($prefix -le 30) {
                $start = $start + 1
                $end = $end - 1
            }
            $parsed = $true
        }
        elseif ($part -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\*$') {
            $prefixText = $Matches[1]
            if (-not (Test-IPv4Address "$prefixText.1")) {
                return [pscustomobject]@{ Ok = $false; Error = "IP 段无效：$prefixText.*"; IPs = @() }
            }
            $start = (Convert-IPv4ToNumber "$prefixText.1")
            $end = (Convert-IPv4ToNumber "$prefixText.254")
            $parsed = $true
        }
        elseif ($part -match '^(.+?)\s*-\s*(.+)$') {
            $left = $Matches[1].Trim()
            $right = $Matches[2].Trim()
            if (-not (Test-IPv4Address $left)) {
                return [pscustomobject]@{ Ok = $false; Error = "范围起始地址无效：$left"; IPs = @() }
            }
            if ($right -match '^\d{1,3}$') {
                $octets = $left.Split('.')
                $right = "$($octets[0]).$($octets[1]).$($octets[2]).$right"
            }
            if (-not (Test-IPv4Address $right)) {
                return [pscustomobject]@{ Ok = $false; Error = "范围结束地址无效：$right"; IPs = @() }
            }
            $start = Convert-IPv4ToNumber $left
            $end = Convert-IPv4ToNumber $right
            if ($start -gt $end) {
                return [pscustomobject]@{ Ok = $false; Error = '范围起始地址不能大于结束地址'; IPs = @() }
            }
            $parsed = $true
        }
        elseif (Test-IPv4Address $part) {
            $start = Convert-IPv4ToNumber $part
            $end = $start
            $parsed = $true
        }

        if (-not $parsed) {
            return [pscustomobject]@{
                Ok = $false
                Error = "无法识别「$part」，请使用 192.168.1.0/24、192.168.1.1-254 或单个 IP"
                IPs = @()
            }
        }

        $count = $end - $start + 1
        if ($count -gt 4096 -or ($all.Count + $count) -gt 4096) {
            return [pscustomobject]@{ Ok = $false; Error = '一次最多扫描 4096 个地址，请缩小网段范围'; IPs = @() }
        }

        for ($i = $start; $i -le $end; $i++) {
            [void]$all.Add((Convert-NumberToIPv4 $i))
        }
    }

    $unique = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($ip in $all) {
        if (-not $seen.ContainsKey($ip)) {
            $seen[$ip] = $true
            [void]$unique.Add($ip)
        }
    }
    $sortedIps = @($unique | Sort-Object { Convert-IPv4ToNumber $_ })
    if ($sortedIps.Count -eq 0) {
        return [pscustomobject]@{ Ok = $false; Error = '没有可扫描的地址'; IPs = @() }
    }
    return [pscustomobject]@{ Ok = $true; Error = ''; IPs = $sortedIps; Raw = $raw }
}

# ---------------------------------------------------------------------------
# Result collection and view
# ---------------------------------------------------------------------------
$script:Rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
$script:View = New-Object System.Windows.Data.ListCollectionView -ArgumentList (, $script:Rows)
$script:View.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('Occupied', [System.ComponentModel.ListSortDirection]::Descending)))
$script:View.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('SortKey', [System.ComponentModel.ListSortDirection]::Ascending)))
$gridResults.ItemsSource = $script:View

$script:FilterMode = 'all'
$script:FilterText = ''
$script:IsScanning = $false
$script:Engine = $null
$script:ScanTimer = $null
$script:Stopwatch = $null
$script:Total = 0
$script:OccupiedCount = 0
$script:FreeCount = 0
$script:TargetLabel = ''
$script:LocalSubnets = @()
$script:LastScanCancelled = $false
$script:StopRequested = $false

function Set-StatusText([string]$text, [string]$color = '#667D9D') {
    $lblStatus.Text = $text
    $lblStatus.Foreground = Get-UiBrush $color
}

function Update-EmptyState {
    if ($script:IsScanning -and $script:Rows.Count -eq 0) {
        $lblEmptyTitle.Text = '正在扫描...'
        $lblEmptyDesc.Text = "正在探测 $($script:TargetLabel)，请稍候"
        $emptyState.Visibility = [System.Windows.Visibility]::Visible
        return
    }
    if ($script:Rows.Count -eq 0) {
        if ($script:LastScanCancelled) {
            $lblEmptyTitle.Text = '扫描已停止'
            $lblEmptyDesc.Text = '可以调整网段范围后重新扫描'
        }
        else {
            $lblEmptyTitle.Text = '还没有扫描结果'
            $lblEmptyDesc.Text = '输入网段后点击“开始扫描”'
        }
        $emptyState.Visibility = [System.Windows.Visibility]::Visible
        return
    }
    if ($script:View.Count -eq 0) {
        $lblEmptyTitle.Text = '没有符合条件的结果'
        $lblEmptyDesc.Text = '试试切换筛选条件或清空搜索关键字'
        $emptyState.Visibility = [System.Windows.Visibility]::Visible
        return
    }
    $emptyState.Visibility = [System.Windows.Visibility]::Collapsed
}

function Update-ResultCount {
    if ($script:View.Count -eq $script:Rows.Count) {
        $lblResultCount.Text = "$($script:Rows.Count) 个结果"
    }
    else {
        $lblResultCount.Text = "$($script:View.Count) / $($script:Rows.Count) 个结果"
    }
}

function Update-Filter {
    if ($rbOccupied.IsChecked) { $script:FilterMode = 'occupied' }
    elseif ($rbFree.IsChecked) { $script:FilterMode = 'free' }
    else { $script:FilterMode = 'all' }

    $script:FilterText = $txtSearch.Text.Trim().ToLowerInvariant()
    if ($script:FilterText.Length -eq 0) {
        $txtSearchHint.Visibility = [System.Windows.Visibility]::Visible
    }
    else {
        $txtSearchHint.Visibility = [System.Windows.Visibility]::Collapsed
    }

    if ($null -ne $script:View) {
        $script:View.Refresh()
    }
    Update-ResultCount
    Update-EmptyState
}

$script:View.Filter = [System.Predicate[object]]{
    param($item)
    if ($null -eq $item) { return $false }
    if ($script:FilterMode -eq 'occupied' -and -not $item.Occupied) { return $false }
    if ($script:FilterMode -eq 'free' -and $item.Occupied) { return $false }
    if ($script:FilterText.Length -gt 0) {
        $haystack = "$($item.IP) $($item.Mac) $($item.HostName)".ToLowerInvariant()
        if (-not $haystack.Contains($script:FilterText)) { return $false }
    }
    return $true
}

# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------
function Format-Latency($result) {
    if (-not $result.Alive) { return '—' }
    if ($result.Method -eq 'ARP') { return '<1 ms' }
    if ($result.Method -eq '本机') { return '本机' }
    if ($result.PingMs -ge 0) { return "$($result.PingMs) ms" }
    return '—'
}

function Add-ScanResult($result) {
    $occupied = [bool]$result.Alive
    $hostName = [string]$result.HostName
    if ([string]::IsNullOrWhiteSpace($hostName)) { $hostName = '—' }
    $mac = [string]$result.Mac
    if ([string]::IsNullOrWhiteSpace($mac)) { $mac = '—' }

    if ($occupied) { $script:OccupiedCount++ } else { $script:FreeCount++ }

    $row = [pscustomobject]@{
        IP       = [string]$result.IP
        State    = $(if ($occupied) { '占用' } else { '未占用' })
        Occupied = $occupied
        Latency  = (Format-Latency $result)
        HostName = $hostName
        Mac      = $mac
        SortKey  = [uint64](Convert-IPv4ToNumber $result.IP)
    }
    $script:Rows.Add($row)
}

function Finish-Scan([bool]$cancelled) {
    if ($null -ne $script:ScanTimer) {
        $script:ScanTimer.Stop()
    }
    $script:IsScanning = $false
    $elapsedText = '0.0 s'
    if ($null -ne $script:Stopwatch) {
        $elapsedText = ('{0:N1} s' -f $script:Stopwatch.Elapsed.TotalSeconds)
    }
    $lblElapsed.Text = $elapsedText
    $lblScanned.Text = "$($script:Rows.Count) / $($script:Total)"
    $script:LastScanCancelled = $cancelled
    $script:StopRequested = $false
    $btnScan.IsEnabled = $true
    $btnStop.Visibility = [System.Windows.Visibility]::Collapsed
    $btnScan.Visibility = [System.Windows.Visibility]::Visible
    $txtTarget.IsEnabled = $true
    $btnLocal.IsEnabled = $true
    $txtScanBtn.Text = '重新扫描'

    if ($cancelled) {
        $lblPercent.Text = "$([int]$barProgress.Value)%"
        Set-StatusText "已停止 · 已扫描 $($script:Rows.Count) / $($script:Total) 个地址 · 发现 $($script:OccupiedCount) 台占用" '#FBBF24'
        $lblEmptyTitle.Text = '扫描已停止'
    }
    else {
        $barProgress.Value = 100
        $lblPercent.Text = '100%'
        if ($script:OccupiedCount -gt 0) {
            Set-StatusText "扫描完成 · $($script:TargetLabel) · 发现 $($script:OccupiedCount) 台占用主机，耗时 $elapsedText" '#8FA5C4'
        }
        else {
            Set-StatusText "扫描完成 · $($script:TargetLabel) · 未发现占用主机，耗时 $elapsedText" '#8FA5C4'
        }
        $lblEmptyTitle.Text = '没有发现占用主机'
        $lblEmptyDesc.Text = '可以尝试扩大网段范围后重新扫描'
    }
    Update-ResultCount
    Update-EmptyState
}

function Update-ScanUi {
    if ($null -eq $script:Engine) { return }

    $added = 0
    while ($added -lt 120) {
        $result = $script:Engine.Next()
        if ($null -eq $result) { break }
        Add-ScanResult $result
        $added++
    }

    if ($added -gt 0) {
        $lblOccupied.Text = [string]$script:OccupiedCount
        $lblFree.Text = [string]$script:FreeCount
        $lblScanned.Text = "$($script:Rows.Count) / $($script:Total)"
        Update-ResultCount
        Update-EmptyState
    }

    $done = $script:Engine.Completed
    if ($done -gt $script:Total) { $done = $script:Total }
    $percent = 0
    if ($script:Total -gt 0) {
        $percent = [int][Math]::Floor(($done * 100.0) / $script:Total)
    }
    $barProgress.Value = $percent
    $lblPercent.Text = "$percent%"

    if ($script:IsScanning) {
        if ($null -ne $script:Stopwatch) {
            $lblElapsed.Text = ('{0:N1} s' -f $script:Stopwatch.Elapsed.TotalSeconds)
        }
        if ($script:StopRequested) {
            Set-StatusText "正在停止扫描 · 已完成 $done / $($script:Total) · 已发现 $($script:OccupiedCount) 台占用" '#FBBF24'
        }
        else {
            Set-StatusText "正在扫描 $($script:TargetLabel) · 已完成 $done / $($script:Total) · 发现 $($script:OccupiedCount) 台占用" '#7FB8D8'
        }
    }

    if ($script:Engine.IsComplete -and $script:Engine.Pending -eq 0) {
        Finish-Scan ([bool]$script:Engine.IsCancelled)
    }
}

function Show-DemoData {
    $script:TargetLabel = '192.168.1.0/24'
    $txtTarget.Text = $script:TargetLabel
    $script:Total = 254
    $script:IsScanning = $false
    $script:LastScanCancelled = $false
    $script:StopRequested = $false
    $script:Rows.Clear()
    $script:OccupiedCount = 0
    $script:FreeCount = 0

    $samples = @(
        @{ IP = '192.168.1.1';  Host = 'router.local';          Mac = 'A4-00-00-00-00-01' },
        @{ IP = '192.168.1.10'; Host = 'DESKTOP-A1B2C3.local';  Mac = '02-00-00-00-00-10' },
        @{ IP = '192.168.1.12'; Host = 'NAS-DEMO.local';        Mac = '02-00-00-00-00-12' },
        @{ IP = '192.168.1.18'; Host = 'PRINTER-01.local';      Mac = '02-00-00-00-00-18' },
        @{ IP = '192.168.1.21'; Host = 'OFFICE-PC-01.local';    Mac = '02-00-00-00-00-21' },
        @{ IP = '192.168.1.25'; Host = 'OFFICE-PC-02.local';    Mac = '02-00-00-00-00-25' },
        @{ IP = '192.168.1.30'; Host = 'IP-CAMERA-01.local';    Mac = '02-00-00-00-00-30' },
        @{ IP = '192.168.1.33'; Host = 'AP-LOBBY.local';        Mac = '02-00-00-00-00-33' },
        @{ IP = '192.168.1.40'; Host = 'SERVER-FILE.local';     Mac = '02-00-00-00-00-40' },
        @{ IP = '192.168.1.45'; Host = 'MEETING-ROOM.local';    Mac = '02-00-00-00-00-45' },
        @{ IP = '192.168.1.50'; Host = 'DESKTOP-DEMO.local';    Mac = '02-00-00-00-00-50' },
        @{ IP = '192.168.1.66'; Host = 'TEST-DEVICE.local';     Mac = '02-00-00-00-00-66' }
    )

    $sampleMap = @{}
    foreach ($sample in $samples) { $sampleMap[$sample.IP] = $sample }

    for ($i = 1; $i -le 254; $i++) {
        $ip = "192.168.1.$i"
        if ($sampleMap.ContainsKey($ip)) {
            $sample = $sampleMap[$ip]
            Add-ScanResult ([pscustomobject]@{
                IP       = $sample.IP
                Alive    = $true
                PingMs   = 0
                Mac      = $sample.Mac
                HostName = $sample.Host
                Method   = 'ARP'
            })
        }
        else {
            Add-ScanResult ([pscustomobject]@{
                IP       = $ip
                Alive    = $false
                PingMs   = -1
                Mac      = ''
                HostName = ''
                Method   = ''
            })
        }
    }

    $lblScanned.Text = '254 / 254'
    $lblOccupied.Text = [string]$script:OccupiedCount
    $lblFree.Text = [string]$script:FreeCount
    $lblElapsed.Text = '7.4 s'
    $barProgress.Value = 100
    $lblPercent.Text = '100%'
    $btnScan.Visibility = [System.Windows.Visibility]::Visible
    $btnScan.IsEnabled = $true
    $btnStop.Visibility = [System.Windows.Visibility]::Collapsed
    $txtTarget.IsEnabled = $true
    $btnLocal.IsEnabled = $true
    $txtScanBtn.Text = '重新扫描'
    Set-StatusText '示例数据 · 192.168.1.0/24 · 发现 12 台占用主机' '#8FA5C4'
    $rbOccupied.IsChecked = $true
    Update-Filter
    Update-EmptyState
}

function Start-Scan {
    if ($script:IsScanning) { return }

    $parsed = Parse-ScanTarget $txtTarget.Text
    if (-not $parsed.Ok) {
        $txtTarget.BorderBrush = Get-UiBrush '#FF5D73'
        Set-StatusText $parsed.Error '#FF6B7E'
        $txtTarget.Focus() | Out-Null
        return
    }

    $txtTarget.BorderBrush = Get-UiBrush '#233553'
    $txtTarget.Text = $parsed.Raw
    $script:TargetLabel = $parsed.Raw
    $script:Total = $parsed.IPs.Count
    $script:OccupiedCount = 0
    $script:FreeCount = 0
    $script:IsScanning = $true
    $script:LastScanCancelled = $false
    $script:StopRequested = $false

    $script:Rows.Clear()
    $script:View.Refresh()
    $lblScanned.Text = "0 / $($script:Total)"
    $lblOccupied.Text = '0'
    $lblFree.Text = '0'
    $lblElapsed.Text = '0.0 s'
    $barProgress.Value = 0
    $lblPercent.Text = '0%'
    $lblResultCount.Text = '0 个结果'
    Set-StatusText "正在扫描 $($script:TargetLabel) · 共 $($script:Total) 个地址" '#7FB8D8'

    $txtTarget.IsEnabled = $false
    $btnLocal.IsEnabled = $false
    $btnScan.IsEnabled = $false
    $btnScan.Visibility = [System.Windows.Visibility]::Collapsed
    $btnStop.Visibility = [System.Windows.Visibility]::Visible
    $btnStop.IsEnabled = $true
    Update-EmptyState

    $script:Engine = New-Object LanScanEngine
    $script:Engine.Start([string[]]$parsed.IPs, 800, 128)
    $script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    if ($null -ne $script:ScanTimer) {
        $script:ScanTimer.Stop()
    }
    $script:ScanTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:ScanTimer.Interval = [TimeSpan]::FromMilliseconds(100)
    $script:ScanTimer.Add_Tick({ Update-ScanUi })
    $script:ScanTimer.Start()
}

function Stop-Scan {
    if ($null -eq $script:Engine -or -not $script:IsScanning) { return }
    $script:Engine.Cancel()
    $script:StopRequested = $true
    $btnStop.IsEnabled = $false
    Set-StatusText '正在停止扫描...' '#FBBF24'
}

# ---------------------------------------------------------------------------
# Event wiring
# ---------------------------------------------------------------------------
$btnScan.Add_Click({ Start-Scan })
$btnStop.Add_Click({ Stop-Scan })

$btnLocal.Add_Click({
    if ($script:LocalSubnets.Count -eq 0) {
        Set-StatusText '未检测到可扫描的本机网段，请手动输入' '#FBBF24'
        return
    }
    if ($script:LocalSubnets.Count -eq 1) {
        $txtTarget.Text = $script:LocalSubnets[0].CIDR
        $txtTarget.BorderBrush = Get-UiBrush '#233553'
        Set-StatusText "已填入本机网段 $($script:LocalSubnets[0].CIDR) · $($script:LocalSubnets[0].Interface)" '#667D9D'
        return
    }

    $menu = New-Object System.Windows.Controls.ContextMenu
    foreach ($subnet in $script:LocalSubnets) {
        $item = New-Object System.Windows.Controls.MenuItem
        $item.Header = "$($subnet.CIDR)    $($subnet.Interface)"
        $item.Tag = $subnet.CIDR
        $item.Add_Click({
            $txtTarget.Text = [string]$this.Tag
            $txtTarget.BorderBrush = Get-UiBrush '#233553'
            Set-StatusText "已填入本机网段 $($txtTarget.Text)" '#667D9D'
        })
        [void]$menu.Items.Add($item)
    }
    $menu.PlacementTarget = $btnLocal
    $menu.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
    $menu.IsOpen = $true
})

$txtTarget.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Enter) {
        Start-Scan
        $e.Handled = $true
    }
})

$txtTarget.Add_TextChanged({
    $txtTarget.BorderBrush = Get-UiBrush '#233553'
})

$txtSearch.Add_TextChanged({ Update-Filter })
$rbAll.Add_Checked({ Update-Filter })
$rbOccupied.Add_Checked({ Update-Filter })
$rbFree.Add_Checked({ Update-Filter })

$btnMin.Add_Click({ $window.WindowState = [System.Windows.WindowState]::Minimized })
$btnMax.Add_Click({
    if ($window.WindowState -eq [System.Windows.WindowState]::Maximized) {
        $window.WindowState = [System.Windows.WindowState]::Normal
    }
    else {
        $window.WindowState = [System.Windows.WindowState]::Maximized
    }
})
$btnClose.Add_Click({ $window.Close() })

$window.Add_StateChanged({
    if ($window.WindowState -eq [System.Windows.WindowState]::Maximized) {
        $btnMax.Content = [string][char]0xE923
        $btnMax.ToolTip = '还原'
    }
    else {
        $btnMax.Content = [string][char]0xE922
        $btnMax.ToolTip = '最大化'
    }
})

$titleDrag.Add_MouseLeftButtonDown({
    param($sender, $e)
    if ($e.ClickCount -eq 2) {
        if ($window.WindowState -eq [System.Windows.WindowState]::Maximized) {
            $window.WindowState = [System.Windows.WindowState]::Normal
        }
        else {
            $window.WindowState = [System.Windows.WindowState]::Maximized
        }
        return
    }
    try { $window.DragMove() } catch { }
})

$window.Add_Closed({
    if ($null -ne $script:ScanTimer) { $script:ScanTimer.Stop() }
    if ($null -ne $script:Engine) { $script:Engine.Cancel() }
})

$window.Add_Loaded({
    $window.Opacity = 0
    $fade = New-Object System.Windows.Media.Animation.DoubleAnimation
    $fade.From = 0
    $fade.To = 1
    $fade.Duration = [System.Windows.Duration]::new([TimeSpan]::FromMilliseconds(240))
    $window.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $fade)

    if ($Demo) {
        Show-DemoData
        return
    }

    if ($AutoStart) {
        $window.Dispatcher.BeginInvoke(
            [System.Action]{ Start-Scan },
            [System.Windows.Threading.DispatcherPriority]::ApplicationIdle
        ) | Out-Null
    }
})

# ---------------------------------------------------------------------------
# Initial target detection
# ---------------------------------------------------------------------------
$script:LocalSubnets = @(Get-LocalSubnets)
if (-not [string]::IsNullOrWhiteSpace($Target)) {
    $txtTarget.Text = $Target
}
elseif ($script:LocalSubnets.Count -gt 0) {
    $txtTarget.Text = $script:LocalSubnets[0].CIDR
}
else {
    $txtTarget.Text = '192.168.1.0/24'
}

if (-not [string]::IsNullOrWhiteSpace($Target)) {
    Set-StatusText "目标 $($txtTarget.Text) · 按 Enter 或点击开始扫描" '#667D9D'
}
elseif ($script:LocalSubnets.Count -gt 0) {
    Set-StatusText "就绪 · 已自动识别本机网段 $($script:LocalSubnets[0].CIDR)（$($script:LocalSubnets[0].Interface)）" '#667D9D'
}
else {
    Set-StatusText '就绪 · 未识别到本机网段，请手动输入' '#667D9D'
}
Update-ResultCount
Update-EmptyState

[void]$window.ShowDialog()
