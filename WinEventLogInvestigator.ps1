#Requires -Version 5.1
#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- GUI Theme Configuration ---
$theme = @{
    FormBackground      = [System.Drawing.Color]::FromArgb(45, 45, 48)
    ControlBackground   = [System.Drawing.Color]::FromArgb(60, 60, 63)
    ControlForeground   = [System.Drawing.Color]::FromArgb(220, 220, 220)
    ButtonBackground    = [System.Drawing.Color]::FromArgb(80, 80, 85)
    ButtonForeground    = [System.Drawing.Color]::FromArgb(240, 240, 240)
    GridBackground      = [System.Drawing.Color]::FromArgb(50, 50, 53)
    GridForeground      = [System.Drawing.Color]::FromArgb(210, 210, 210)
    GridHeaderBackground= [System.Drawing.Color]::FromArgb(70, 70, 73)
    GridHeaderForeground= [System.Drawing.Color]::White
    GridCellBackground  = [System.Drawing.Color]::FromArgb(60, 60, 63)
    GridAltCellBackground= [System.Drawing.Color]::FromArgb(65, 65, 68)
    GridSelectionBackground = [System.Drawing.Color]::FromArgb(0, 122, 204)
    GridSelectionForeground = [System.Drawing.Color]::White
    AccentColor         = [System.Drawing.Color]::FromArgb(0, 122, 204)
}

# --- Global Variables ---
$script:AllEventsData = @()
$script:FilteredEventsData = @()
$script:EventLogJob = $null

# --- Event Log Definitions ---
$timeFrames = @(
    [PSCustomObject]@{Name="Last 1 hour";Hours=-1},
    [PSCustomObject]@{Name="Last 6 hours";Hours=-6},
    [PSCustomObject]@{Name="Last 12 hours";Hours=-12},
    [PSCustomObject]@{Name="Last 24 hours";Hours=-24},
    [PSCustomObject]@{Name="Last 48 hours";Hours=-48},
    [PSCustomObject]@{Name="Last 3 days (72 hours)";Hours=-72},
    [PSCustomObject]@{Name="Last 1 week";Hours=-168}
)

# --- GUI Element Creation ---
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "Windows Event Log Investigator"
$mainForm.Size = New-Object System.Drawing.Size(1000, 700)
$mainForm.MinimumSize = New-Object System.Drawing.Size(800, 500)
$mainForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$mainForm.BackColor = $theme.FormBackground
$mainForm.ForeColor = $theme.ControlForeground
$mainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

$topPanel = New-Object System.Windows.Forms.Panel
$topPanel.Height = 90 
$topPanel.Dock = [System.Windows.Forms.DockStyle]::Top 
$topPanel.BackColor = $theme.FormBackground
$topPanel.Padding = New-Object System.Windows.Forms.Padding(5) 

$lblTimeFrame = New-Object System.Windows.Forms.Label; $lblTimeFrame.Text = "Time Frame:"; $lblTimeFrame.Location = New-Object System.Drawing.Point(10, 15); $lblTimeFrame.AutoSize = $true
$cmbTimeFrame = New-Object System.Windows.Forms.ComboBox; $cmbTimeFrame.Location = New-Object System.Drawing.Point(90, 12); $cmbTimeFrame.Size = New-Object System.Drawing.Size(170, 25); $cmbTimeFrame.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $timeFrames | ForEach-Object { [void]$cmbTimeFrame.Items.Add($_.Name) }; $cmbTimeFrame.SelectedIndex = 2; $cmbTimeFrame.BackColor = $theme.ControlBackground; $cmbTimeFrame.ForeColor = $theme.ControlForeground; $cmbTimeFrame.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$btnGetEvents = New-Object System.Windows.Forms.Button; $btnGetEvents.Text = "Get Events"; $btnGetEvents.Location = New-Object System.Drawing.Point(([int]$cmbTimeFrame.Right + 20), 10); $btnGetEvents.Size = New-Object System.Drawing.Size(100, 30); $btnGetEvents.BackColor = $theme.ButtonBackground; $btnGetEvents.ForeColor = $theme.ButtonForeground; $btnGetEvents.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $btnGetEvents.FlatAppearance.BorderColor = $theme.AccentColor; $btnGetEvents.FlatAppearance.BorderSize = 1
$btnExportOpen = New-Object System.Windows.Forms.Button; $btnExportOpen.Text = "View in CSV"; $btnExportOpen.Location = New-Object System.Drawing.Point(([int]$btnGetEvents.Right + 10), 10); $btnExportOpen.Size = New-Object System.Drawing.Size(120, 30); $btnExportOpen.BackColor = $theme.ButtonBackground; $btnExportOpen.ForeColor = $theme.ButtonForeground; $btnExportOpen.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $btnExportOpen.FlatAppearance.BorderColor = $theme.AccentColor; $btnExportOpen.FlatAppearance.BorderSize = 1

$chkClusterEvents = New-Object System.Windows.Forms.CheckBox; $chkClusterEvents.Text = "Cluster"; $chkClusterEvents.Location = New-Object System.Drawing.Point(10, 52); $chkClusterEvents.AutoSize = $true; $chkClusterEvents.Checked = $false; $chkClusterEvents.ForeColor = $theme.ControlForeground
$chkOpsManagerEvents = New-Object System.Windows.Forms.CheckBox; $chkOpsManagerEvents.Text = "OpsMgr"; $chkOpsManagerEvents.AutoSize = $true; $chkOpsManagerEvents.Checked = $false; $chkOpsManagerEvents.ForeColor = $theme.ControlForeground
$chkSqlEvents = New-Object System.Windows.Forms.CheckBox; $chkSqlEvents.Text = "SQL"; $chkSqlEvents.AutoSize = $true; $chkSqlEvents.Checked = $false; $chkSqlEvents.ForeColor = $theme.ControlForeground

$lblFilterEventID = New-Object System.Windows.Forms.Label; $lblFilterEventID.Text = "Filter IDs:"; $lblFilterEventID.AutoSize = $true
$txtFilterEventID = New-Object System.Windows.Forms.TextBox; $txtFilterEventID.Size = New-Object System.Drawing.Size(150, 25); $txtFilterEventID.BackColor = $theme.ControlBackground; $txtFilterEventID.ForeColor = $theme.ControlForeground; $txtFilterEventID.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$lblFilterHelp = New-Object System.Windows.Forms.Label; $lblFilterHelp.Text = "(?)"; $lblFilterHelp.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold); $lblFilterHelp.AutoSize = $true
$filterToolTip = New-Object System.Windows.Forms.ToolTip; $filterToolTip.SetToolTip($lblFilterHelp, "IDs: comma/space separated. E.g., '1001, -7036'"); $filterToolTip.SetToolTip($txtFilterEventID, "E.g., '1001, 4624' or '-7036' to exclude.")
$btnClearFilter = New-Object System.Windows.Forms.Button; $btnClearFilter.Text = "Clear"; $btnClearFilter.Size = New-Object System.Drawing.Size(70, 28); $btnClearFilter.BackColor = $theme.ButtonBackground; $btnClearFilter.ForeColor = $theme.ButtonForeground; $btnClearFilter.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat; $btnClearFilter.FlatAppearance.BorderColor = $theme.AccentColor; $btnClearFilter.FlatAppearance.BorderSize = 1

$mainForm.Add_Shown({ 
    $chkOpsManagerEvents.Location = New-Object System.Drawing.Point(([int]$chkClusterEvents.Right + 10), 52) 
    $chkSqlEvents.Location = New-Object System.Drawing.Point(([int]$chkOpsManagerEvents.Right + 10), 52)
    $filterGroupStartX = ([int]$chkSqlEvents.Right + 25) 
    $lblFilterEventID.Location = New-Object System.Drawing.Point($filterGroupStartX, 54) 
    $txtFilterEventID.Location = New-Object System.Drawing.Point(([int]$lblFilterEventID.Right + 5), 52)
    $lblFilterHelp.Location = New-Object System.Drawing.Point(([int]$txtFilterEventID.Right + 5), 53)
    $btnClearFilter.Location = New-Object System.Drawing.Point(([int]$lblFilterHelp.Right + 7), 50)
})

$topPanel.Controls.AddRange(@($lblTimeFrame, $cmbTimeFrame, $btnGetEvents, $btnExportOpen, $chkClusterEvents, $chkOpsManagerEvents, $chkSqlEvents, $lblFilterEventID, $txtFilterEventID, $lblFilterHelp, $btnClearFilter))

$statusBar = New-Object System.Windows.Forms.StatusStrip; $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel "Ready."; $statusLabel.ForeColor = $theme.ControlForeground; $statusBar.Items.Add($statusLabel); $statusBar.BackColor = $theme.FormBackground; $statusBar.Dock = [System.Windows.Forms.DockStyle]::Bottom
$dgvEvents = New-Object System.Windows.Forms.DataGridView; $dgvEvents.Dock = [System.Windows.Forms.DockStyle]::Fill
$dgvEvents.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
$dgvEvents.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::None 
$dgvEvents.ReadOnly = $true; $dgvEvents.MultiSelect = $true; $dgvEvents.AllowUserToAddRows = $false; $dgvEvents.AllowUserToDeleteRows = $false
$dgvEvents.BackgroundColor = $theme.GridBackground; $dgvEvents.ForeColor = $theme.GridForeground
$dgvEvents.DefaultCellStyle.BackColor = $theme.GridCellBackground; $dgvEvents.DefaultCellStyle.ForeColor = $theme.GridForeground
$dgvEvents.DefaultCellStyle.SelectionBackColor = $theme.GridSelectionBackground; $dgvEvents.DefaultCellStyle.SelectionForeColor = $theme.GridSelectionForeground
$dgvEvents.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAltCellBackground
$dgvEvents.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHeaderBackground; $dgvEvents.ColumnHeadersDefaultCellStyle.ForeColor = $theme.GridHeaderForeground
$dgvEvents.EnableHeadersVisualStyles = $false; $dgvEvents.RowHeadersVisible = $false
$dgvEvents.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$dgvEvents.ScrollBars = [System.Windows.Forms.ScrollBars]::Both 

$ctxMenu = New-Object System.Windows.Forms.ContextMenuStrip; $selectAllMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem "Select All"; $selectAllMenuItem.ShortcutKeys = ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::A); $copyMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem "Copy Selected"; $copyMenuItem.ShortcutKeys = ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::C); $exportCsvMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem "Export Displayed to CSV..."; $ctxMenu.Items.AddRange(@($selectAllMenuItem, $copyMenuItem, $exportCsvMenuItem)); $dgvEvents.ContextMenuStrip = $ctxMenu
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 1000
Function Update-StatusBar ($text, [Switch]$ErrorState) { $statusLabel.Text = $text; if ($ErrorState) { $statusLabel.ForeColor = [System.Drawing.Color]::OrangeRed } else { $statusLabel.ForeColor = $theme.ControlForeground }; $statusBar.Refresh() }

Function Populate-DataGridView ($data) {
    $dgvEvents.DataSource = $null; $dgvEvents.AutoGenerateColumns = $false; $dgvEvents.Columns.Clear()
    if ($data -and $data.Count -gt 0) {
        $colTimeCreated = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colTimeCreated.DataPropertyName = "TimeCreated"; $colTimeCreated.Name = "TimeCreated"; $colTimeCreated.HeaderText = "Time Created"; $colTimeCreated.DefaultCellStyle.Format = "yyyy-MM-dd HH:mm:ss.fff"; $colTimeCreated.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
        $colId = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colId.DataPropertyName = "Id"; $colId.Name = "Id"; $colId.HeaderText = "Event ID"; $colId.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
        $colLevel = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colLevel.DataPropertyName = "LevelDisplayName"; $colLevel.Name = "LevelDisplayName"; $colLevel.HeaderText = "Level"; $colLevel.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
        $colProvider = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colProvider.DataPropertyName = "ProviderName"; $colProvider.Name = "ProviderName"; $colProvider.HeaderText = "Provider"; $colProvider.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells
        $colMessage = New-Object System.Windows.Forms.DataGridViewTextBoxColumn; $colMessage.DataPropertyName = "Message"; $colMessage.Name = "Message"; $colMessage.HeaderText = "Message"; $colMessage.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::None; $colMessage.Width = 600; $colMessage.MinimumWidth = 300 
        $dgvEvents.Columns.AddRange($colTimeCreated, $colId, $colLevel, $colProvider, $colMessage)
        $dgvEvents.DataSource = [System.Collections.ArrayList]$data
        foreach ($column in $dgvEvents.Columns) { $column.SortMode = [System.Windows.Forms.DataGridViewColumnSortMode]::Automatic }
    }
}

Function Apply-EventIdFilter {
    $filterInputString = $txtFilterEventID.Text.Trim(); $currentDataToFilter = $script:AllEventsData
    if (-not $currentDataToFilter) { $script:FilteredEventsData = @(); Populate-DataGridView $script:FilteredEventsData; Update-StatusBar "No data to filter."; return }
    if ([string]::IsNullOrWhiteSpace($filterInputString)) { $script:FilteredEventsData = $currentDataToFilter } else {
        $includeIDs = [System.Collections.Generic.List[int]]::new(); $excludeIDs = [System.Collections.Generic.List[int]]::new()
        $tokens = $filterInputString -split '[, ]' | Where-Object {$_ -ne ""}; foreach ($token in $tokens) { if ($token.StartsWith("-")) { $idStr = $token.Substring(1); if ($idStr -match "^\d+$") { [void]$excludeIDs.Add([int]$idStr) } } elseif ($token -match "^\d+$") { [void]$includeIDs.Add([int]$token) } }
        $tempFilteredData = $currentDataToFilter; if ($includeIDs.Count -gt 0) { $tempFilteredData = $tempFilteredData | Where-Object { $includeIDs -contains $_.Id } }; if ($excludeIDs.Count -gt 0) { $tempFilteredData = $tempFilteredData | Where-Object { -not ($excludeIDs -contains $_.Id) } }; $script:FilteredEventsData = $tempFilteredData
    }
    Populate-DataGridView $script:FilteredEventsData; $currentAllCount = if ($script:AllEventsData) { $script:AllEventsData.Count } else { 0 }; $currentFilteredCount = if ($script:FilteredEventsData) { $script:FilteredEventsData.Count } else { 0 }
    Update-StatusBar "Displaying ${currentFilteredCount} of ${currentAllCount} events."
}

# --- Event Handlers ---
$btnGetEvents.Add_Click({
    $btnGetEvents.Enabled = $false; $btnExportOpen.Enabled = $false; $cmbTimeFrame.Enabled = $false; $chkClusterEvents.Enabled = $false; $chkOpsManagerEvents.Enabled = $false; $chkSqlEvents.Enabled = $false; Update-StatusBar "Initializing event retrieval..."; $dgvEvents.DataSource = $null
    $selectedTimeFrame = $timeFrames[$cmbTimeFrame.SelectedIndex]; $offsetHours = $selectedTimeFrame.Hours
    $includeCluster = $chkClusterEvents.Checked
    $includeOpsMgr = $chkOpsManagerEvents.Checked
    $includeSql = $chkSqlEvents.Checked

    $fetchScriptBlock = { 
        param($OffsetHoursParam, $IncludeClusterEventsParam, $IncludeOpsManagerEventsParam, $IncludeSqlEventsParam)

        Function Get-EventIDListForJobInternal {
            param (
                [bool]$PIncludeOpsMgr,
                [bool]$PIncludeSql,
                [bool]$PIncludeCluster
            )
            $logAndIds = @{}

            # --- Application Log IDs ---
            # Default Application IDs (Original script implied these, plus LoadPerf)
            # Event 1704 removed as per request.
            $appEventIdsList = [System.Collections.Generic.List[int]]@(
                1002, # App Crashes, WER, LoadPerf    
                1705, 1500, 1501 # GPO
            ) # Other app events like 4097, 9009, 26 are less common for "default RCA"
            
            if ($PIncludeSql) {
                # AddRange needs an IEnumerable of the correct type.
                $sqlIdsToAdd = [System.Collections.Generic.List[int]]@(17147, 17137, 17803, 18456)
                $appEventIdsList.AddRange($sqlIdsToAdd)
            }
            if ($appEventIdsList.Count -gt 0) { $logAndIds["Application"] = [int[]]$appEventIdsList }

            # --- System Log IDs (Default from original + expanded) ---
            # These are the critical ones from your original output and essential RCA.
            $systemEventIdsList = [System.Collections.Generic.List[int]]@(
              
                # === Power / Boot / Shutdown ===
                # 1,     # Kernel-General: System boot  - Too general, not included
                12,    # Kernel-General: System shutdown
                13,    # Kernel-General: System restart
                41,    # Kernel-Power: The system has rebooted without a clean shutdown (e.g. BSOD/power loss)
                109,   # Kernel-Power: Kernel power manager shutdown
                1074,  # User32: Planned restart/shutdown initiated by user or process
                1076,  # User32: Unplanned restart/shutdown

                # === Service Control Manager (SCM) ===
                #7000,  # SCM: Service start failure
                #7001,  # SCM: Dependent service failed to start
                #7022,  # SCM: Service hung on startup
                #7023,  # SCM: Service terminated with error status
                #7024,  # SCM: Service terminated with specific exit code
                #7031,  # SCM: Service terminated unexpectedly
                #7034,  # SCM: Service terminated unexpectedly (no auto-restart)
                #7036,  # SCM: Service state change notification

                # === Windows Update Client ===
                19,    # WindowsUpdateClient: Update successful
                20,    # WindowsUpdateClient: Update failed
                26    # WindowsUpdateClient: Update deferred

                # === Group Policy / Userenv ===
                #   1500,  # Userenv: GPO applied successfully
                #   1501,  # Userenv: GPO application failed
                #   1705,  # PerfNet: Performance counter registry keys updated by GPO

                # === Resource‐Exhaustion / Memory ===
                #2004,  # Resource-Exhaustion-Detector: Low virtual memory condition
                #2019,  # SRV: The server was unable to allocate memory from the nonpaged pool
                #2020,  # SRV: The server was unable to allocate memory from the paged pool
                #32021,  # SRV: Server ran out of work items
                #2022,  # SRV: Server ran out of non-blocking work items

                # === Disk / I/O ===
                #7,     # Disk: The device has a bad block
                #51,    # Disk: An error was detected on device during a paging operation
                #57,    # NTFS: Delayed write failed
                #129,   # StorPort: Reset to device (I/O timeout)
                #153,   # Disk: I/O operation retried
                #8193,  # VSS: Volume Shadow Copy Service error  

                # === Driver / Plug-and-Play ===
                #43,    # Kernel-PnP: Driver failed to start
                #44     # Kernel-PnP: Driver loaded successfully
              
     
                # === Application and System Crashes ===
                #1000,  # Application Error: Application crashed
                #1001,  # Windows Error Reporting: Fault bucket info for crashes (with crash dump reference)
        
            )
            # Add more from the comprehensive list if they are general enough
            $systemEventIdsList.AddRange(@(1076, 7000, 7001, 7022, 7023, 7024, 7031, 7034, 7036, 43, 44))

            if ($systemEventIdsList.Count -gt 0) { $logAndIds["System"] = [int[]]$systemEventIdsList }
            
            if ($PIncludeOpsMgr) { 
                $opsMgrIds = [int[]]@(1102, 1103, 4502, 4506, 20000, 20020, 20022, 21016, 21034, 26004) 
                if ($opsMgrIds.Count -gt 0) { $logAndIds["Operations Manager"] = $opsMgrIds }
            }

            if ($PIncludeCluster) {
                $clusterOpIds = [int[]]@(1069, 1135, 1146, 1201, 1202, 1205, 1230, 1254, 1557, 1558, 1561, 1573, 1626, 1650, 1726, 1794, 5120, 5121, 5142)
                if ($clusterOpIds.Count -gt 0) { $logAndIds["Microsoft-Windows-FailoverClustering/Operational"] = $clusterOpIds }
                
                $clusterDiagIds = [int[]]@(2050, 2051)
                if ($clusterDiagIds.Count -gt 0) { $logAndIds["Microsoft-Windows-FailoverClustering/Diagnostic"] = $clusterDiagIds }
            }
            return $logAndIds
        }
        
        $startTimeJob = (Get-Date).AddHours($OffsetHoursParam) 
        $currentEventIDsForLogsJob = Get-EventIDListForJobInternal -PIncludeOpsMgr $IncludeOpsManagerEventsParam -PIncludeSql $IncludeSqlEventsParam -PIncludeCluster $IncludeClusterEventsParam

        $rawRetrievedEventsListJob = [System.Collections.Generic.List[System.Management.Automation.PSObject]]::new()
        $totalLogsToProcessJob = $currentEventIDsForLogsJob.Keys.Count; $processedLogCountJob = 0
        
        foreach ($logNameKeyInLoopJob in $currentEventIDsForLogsJob.Keys) { 
            $processedLogCountJob++; 
            if ($Job) { $Job.UserState = "Processing log ${processedLogCountJob} of ${totalLogsToProcessJob}: ${logNameKeyInLoopJob}..." }
            
            $idsToFilterJob = $currentEventIDsForLogsJob[$logNameKeyInLoopJob]
            if (-not $idsToFilterJob -or $idsToFilterJob.Count -eq 0) { Write-Warning "Skipping log (no IDs to filter): ${logNameKeyInLoopJob}"; continue }
            
            $filterHashTableJob = @{ LogName = $logNameKeyInLoopJob; StartTime = $startTimeJob; Id = $idsToFilterJob }
            try { 
                $foundEventsJob = Get-WinEvent -FilterHashtable $filterHashTableJob -ErrorAction SilentlyContinue
                if ($foundEventsJob) { 
                    $eventsCollectionJob = @($foundEventsJob) 
                    foreach ($eventRecordJob in $eventsCollectionJob) { 
                        if ($eventRecordJob -ne $null) { $rawRetrievedEventsListJob.Add([System.Management.Automation.PSObject]$eventRecordJob) } 
                    } 
                } 
            } catch { Write-Warning "Error retrieving events from ${logNameKeyInLoopJob} in job: $($_.Exception.Message)" } 
        }
        if ($rawRetrievedEventsListJob.Count -eq 0) { return $null }; return $rawRetrievedEventsListJob
    }
    $script:EventLogJob = Start-Job -ScriptBlock $fetchScriptBlock -ArgumentList $offsetHours, $includeCluster, $includeOpsMgr, $includeSql -Name "EventLogFetcher"; $timer.Start()
})

$btnExportOpen.Add_Click({ if ($script:FilteredEventsData -and $script:FilteredEventsData.Count -gt 0) { $tempFilePath = Join-Path $env:TEMP "EventLogReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"; try { $script:FilteredEventsData | Export-Csv -Path $tempFilePath -NoTypeInformation -UseCulture -Encoding UTF8; Update-StatusBar "Data exported to ${tempFilePath}"; Start-Process notepad.exe $tempFilePath } catch { Update-StatusBar "Error exporting or opening data: $($_.Exception.Message)" -ErrorState $true; [System.Windows.Forms.MessageBox]::Show("Error exporting or opening data:`n$($_.Exception.Message)","Export Error","OK","Error") } } else { Update-StatusBar "No data to export."; [System.Windows.Forms.MessageBox]::Show("There is no data to export.","No Data","OK","Warning") } })

$timer.Add_Tick({ if ($script:EventLogJob) { 
    $jobState = $script:EventLogJob.State; $statusText = "Fetching: $($script:EventLogJob.Name) - $($jobState)..."
    If ($script:EventLogJob.UserState) { $statusText = $script:EventLogJob.UserState } ElseIf ($jobState -ne [System.Management.Automation.JobState]::Running -and $jobState -ne [System.Management.Automation.JobState]::NotStarted) { $statusText = "Job $($script:EventLogJob.Name) - $($jobState)... Finalizing." }
    Update-StatusBar $statusText
    if ($jobState -in ([System.Management.Automation.JobState]::Completed, [System.Management.Automation.JobState]::Failed, [System.Management.Automation.JobState]::Stopped)) {
        $timer.Stop(); if ($jobState -eq [System.Management.Automation.JobState]::Completed) {
            $rawJobData = Receive-Job $script:EventLogJob; if ($rawJobData) { $script:AllEventsData = $rawJobData | ForEach-Object { [PSCustomObject]@{ TimeCreated = $_.TimeCreated; Id = $_.Id; LevelDisplayName = $_.LevelDisplayName; ProviderName = $_.ProviderName; Message = ($_.Message -replace '[\r\n]+',' ' -replace '\|', ';') } } | Sort-Object TimeCreated } else { $script:AllEventsData = @() }
            Apply-EventIdFilter; if (-not $rawJobData -and (-not $script:AllEventsData -or $script:AllEventsData.Count -eq 0) ) { Update-StatusBar "No events found matching the criteria." }
        } else { $reason = "Unknown reason"; if ($script:EventLogJob.JobStateInfo -and $script:EventLogJob.JobStateInfo.Reason) { $reason = $script:EventLogJob.JobStateInfo.Reason }; Update-StatusBar "Job $($script:EventLogJob.Name) ${jobState}: ${reason}" -ErrorState $true; if ($script:EventLogJob.ChildJobs[0].Error.Count -gt 0) { $errorMessages = ($script:EventLogJob.ChildJobs[0].Error | ForEach-Object { $_.ToString() }) -join "`n"; [System.Windows.Forms.MessageBox]::Show("Job failed with errors:`n${errorMessages}", "Job Error","OK","Error") } }
        Remove-Job $script:EventLogJob -Force ; $script:EventLogJob = $null; $btnGetEvents.Enabled = $true; $btnExportOpen.Enabled = $true; $cmbTimeFrame.Enabled = $true; $chkClusterEvents.Enabled = $true; $chkOpsManagerEvents.Enabled = $true; $chkSqlEvents.Enabled = $true
    } }})

$txtFilterEventID.Add_TextChanged({ Apply-EventIdFilter })
$btnClearFilter.Add_Click({ $txtFilterEventID.Text = "" })
$selectAllMenuItem.Add_Click({ $dgvEvents.SelectAll() })
$copyMenuItem.Add_Click({ if ($dgvEvents.GetClipboardContent()) { [System.Windows.Forms.Clipboard]::SetDataObject($dgvEvents.GetClipboardContent()); Update-StatusBar "Selected rows copied to clipboard." } })

$exportCsvMenuItem.Add_Click({ 
    if ($script:FilteredEventsData -and $script:FilteredEventsData.Count -gt 0) {
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*"
        $saveFileDialog.Title = "Export Displayed Event Data"
        $saveFileDialog.FileName = "FilteredEventLogReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $script:FilteredEventsData | Export-Csv -Path $saveFileDialog.FileName -NoTypeInformation -UseCulture -Encoding UTF8
                Update-StatusBar "Data exported to $($saveFileDialog.FileName)"
                [System.Windows.Forms.MessageBox]::Show("Data exported successfully to $($saveFileDialog.FileName)","Export Complete","OK","Information")
            } catch {
                Update-StatusBar "Error exporting data: $($_.Exception.Message)" -ErrorState $true
                [System.Windows.Forms.MessageBox]::Show("Error exporting data:`n$($_.Exception.Message)","Export Error","OK","Error")
            }
        }
    } else {
        Update-StatusBar "No data to export."
        [System.Windows.Forms.MessageBox]::Show("There is no data to export.","No Data","OK","Warning")
    }
})

# Add controls to form
$mainForm.Controls.Add($dgvEvents) 
$mainForm.Controls.Add($topPanel)  
$mainForm.Controls.Add($statusBar) 

$mainForm.ShowDialog() | Out-Null
if ($timer.Enabled) { $timer.Stop() }
if ($script:EventLogJob) { try { Stop-Job $script:EventLogJob -Force } catch {}; try { Remove-Job $script:EventLogJob -Force } catch {} }
$mainForm.Dispose()
