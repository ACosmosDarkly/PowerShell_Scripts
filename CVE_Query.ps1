<##################
    GUI INITIALIZATION
##################>

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# GUI window 
$Form                    = New-Object System.Windows.Forms.Form
$Form.ClientSize         = '600,300'
$Form.Text               = "CVE Selection Form"
$Form.TopMost            = $false

# Calendar label
$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Select search date"
$Label1.AutoSize                 = $true
$Label1.width                    = 25
$Label1.height                   = 10
$Label1.location                 = New-Object System.Drawing.Point(20,20)
$Label1.Font                     = 'Microsoft Sans Serif,10'
$form.Controls.Add($Label1)

# Handler for calendar
$Handler_Calendar_DateSelected = {
    $Global:SelectedDate = $($Calendar.SelectionStart.ToShortDateString())
    }

# Calendar object
$Calendar = New-Object Windows.Forms.MonthCalendar
$Calendar.ShowTodayCircle        = $True
$Calendar.MaxSelectionCount      = 1 
$Calendar.Size                   = New-Object System.Drawing.Size(200,200)
$Calendar.Location               = New-Object System.Drawing.Size(20,40)
$Calendar.add_DateSelected($Handler_Calendar_DateSelected)
$form.Controls.Add($Calendar)

# Severity level label
$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "(Optional) Select severity"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(300,20)
$Label2.Font                     = 'Microsoft Sans Serif,10'
$form.Controls.Add($Label2)

# Severity level drop down
$severityLevel                    = New-Object System.Windows.Forms.ComboBox
$severityLevel.Location           = New-Object System.Drawing.Size(305,40)
$severityLevel.Size               = New-Object System.Drawing.Size(60,125)
$severityLevel.Items.Add("Low")
$severityLevel.Items.Add("Medium")
$severityLevel.Items.Add("High")
$severityLevel.Items.Add("Critical")
$form.Controls.Add($severityLevel)

# Keyword text box label
$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "(Optional) Enter filter keywords, one per line"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(300,80)
$Label3.Font                     = 'Microsoft Sans Serif,10'
$form.Controls.Add($Label3)

# Keywork text box object
$outputBox = New-Object System.Windows.Forms.TextBox 
$outputBox.width              = 250
$outputBox.height             = 100
$outputBox.location           = New-Object System.Drawing.Point(305,100)
$outputBox.MultiLine = $True 
$outputBox.ScrollBars = "Vertical"
$form.Controls.Add($outputBox)

# OK button object
$okButton                 = New-Object System.Windows.Forms.Button
$okButton.Text            = "OK"
$okButton.Width           = 80
$okButton.Height          = 25
$okButton.Location        = New-Object System.Drawing.Point(415,250)
$okButton.Font            = 'Microsoft Sans Serif,9'
$okButton.DialogResult    = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($okButton)

# Cancel button object
$cancelButton                 = New-Object System.Windows.Forms.Button
$cancelButton.Text            = "Cancel"
$cancelButton.Width           = 80
$cancelButton.Height          = 25
$cancelButton.Location        = New-Object System.Drawing.Point(500,250)
$cancelButton.Font            = 'Microsoft Sans Serif,9'
$cancelButton.DialogResult    = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($cancelButton)

$result = $Form.ShowDialog()

<##################
    CLASS DEFINITIONS
##################>

class CVE {
    [string]$id
    [decimal]$score
    [string]$severity
    [string]$description

    # Default Constructor
    CVE() {
        $this.id = "Undefined"
    }

    # Main Constructor (Parameterized)
    CVE(
        [string]$i,
        [decimal]$s,
        [string]$se,
        [string]$d
    ) {
        $this.id = $i
        $this.score = $s
        $this.severity = $se
        $this.description = $d
    }
}


<##################
    FUNCTION DEFINITIONS
##################>

function Set-CalendarDateTime {

    param (
        $SelectedDate
    )

        $toDate = [datetime]$SelectedDate
        $toDate = $toDate.ToString("yyyy-MM-dd'T'HH:mm:ss")

    return $toDate
}

function Set-Severity {
    
    param (
        $severity
    )

    if ($severityLevel.Text.Length -gt 0) {
        $severity = $severityLevel.Text
    }

    return $severity
}

function Invoke-CveRestMethod {
    
    param (
        $toDate,
        $fromDate,
        $severity,
        $outputBox
    )

    $flags = ""

    if($severity.Length -gt 0) { 
        $flags = $flags+"s"
        $severity = $severity.ToUpper()
    }
    if($outputBox.Text.Length -gt 0) { $flags = $flags+"o"}

    Switch ($flags) {
    
    "" {$output = Invoke-RestMethod -Method GET -Uri "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=$($toDate):000 UTC-05:00&pubEndDate=$($fromDate):000 UTC-05:00&resultsPerPage=200"}

    "s" {$output = Invoke-RestMethod -Method GET -Uri "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=$($toDate):000 UTC-05:00&pubEndDate=$($fromDate):000 UTC-05:00&cvssV3Severity=$($severity)&resultsPerPage=200"}

    "o" {
        $output = @()
        ForEach ($line in $($outputBox.Text -split "`r`n")) {
            $output += Invoke-RestMethod -Method GET -Uri "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=$($toDate):000 UTC-05:00&pubEndDate=$($fromDate):000 UTC-05:00&keyword=$($line)&resultsPerPage=200"
        }
    }

    "so" {
        $output = @()
        ForEach ($line in $($outputBox.Text -split "`r`n")) {
            $output += Invoke-RestMethod -Method GET -Uri "https://services.nvd.nist.gov/rest/json/cves/1.0/?pubStartDate=$($toDate):000 UTC-05:00&pubEndDate=$($fromDate):000 UTC-05:00&keyword=$($line)&cvssV3Severity=$($severity)&resultsPerPage=200"
        }
    }

    default {return 9}
    
    }

    return $output
}


<##################
    MAIN SCRIPT
##################>

if ($result -eq [System.Windows.Forms.DialogResult]::Ok) {
    $fromDate = Get-Date -Format yyyy-MM-dd'T'HH:mm:ss
    $toDate = Set-CalendarDateTime -SelectedDate $SelectedDate
    if ($severityLevel.Text -gt 0) {
        $severity = Set-Severity -severity $severityLevel
    }
    $output = Invoke-CveRestMethod -toDate $toDate -fromDate $fromDate -severity $severity -outputBox $outputBox

    foreach($line in $output.result.CVE_Items) {
        $cve = [CVE]::new()
        $cve.id = $line.cve.CVE_Data_Meta.ID
        $cve.score = $line.impact.baseMetricV3.cvssV3.baseScore
        $cve.severity = $line.impact.baseMetricV3.cvssV3.baseSeverity
        $cve.description = $line.cve.description.description_data.value
        $cve | Export-Csv C:\temp\CVE_Query.csv -Append -NoTypeInformation
    }

    # Clears variables associated with the GUI so they won't carry over into subsequent runs
    $Form = $null

    return 0
}

if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
    return 1
}