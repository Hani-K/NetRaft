Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$FormObject      = [System.Windows.Forms.Form]
$LabelObject     = [System.Windows.Forms.Label]
$ComboBoxObject  = [System.Windows.Forms.ComboBox]
$ButtonObject    = [System.Windows.Forms.Button]
$TextBoxObject = [System.Windows.Forms.TextBox]
$RichTextBoxObject = [Windows.Forms.RichTextBox]
$MaskedTextBoxObject = [System.Windows.Forms.MaskedTextBox]
$ButtonObject = [System.Windows.Forms.Button]
$LinkLabelObject = [Windows.Forms.LinkLabel]
$fontStyler = [System.Drawing.FontStyle]

$boldFont = $fontStyler::Bold
$italicFont = $fontStyler::Italic
$underlineFont = $fontStyler::Underline
$DefaultFont = New-Object System.Drawing.Font('Arial',10,$boldFont) # Calibri
$DefauktBtnFont = New-Object Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)

# Download the icon
$iconUrl = "https://raw.githubusercontent.com/Hani-K/NetRaft/main/assets/raftnet.ico"
$webClient = New-Object System.Net.WebClient
$iconBytes = $webClient.DownloadData($iconUrl)
$icon = New-Object System.Drawing.Icon ([System.IO.MemoryStream]::new($iconBytes))


# Setup base form
$AppForm = New-Object $FormObject
$AppForm.ClientSize = '500,700'
$AppForm.Text = 'NetRaft - Network Troubleshooter'
$AppForm.BackColor = '#ffffff'
$AppForm.Font = $DefaultFont
$AppForm.FormBorderStyle = "FixedSingle"
$AppForm.StartPosition = "CenterScreen"
$AppForm.BackColor = "#666666"
$AppForm.Icon = $icon
#$AppForm.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
#$AppForm.AutoScaleDimensions = New-Object Drawing.SizeF(96, 96)

# Links
$lblGithubLink = New-Object $LinkLabelObject
$lblGithubLink.Text = "GitHub - Hani K."
$lblGithubLink.Location = New-Object Drawing.Point(385, 680)
$lblGithubLink.Size = New-Object Drawing.Size(300, 20)
$lblGithubLink.Font = New-Object System.Drawing.Font('Lucida Console',8)
$lblGithubLink.LinkColor = [System.Drawing.Color]::LightGreen
$lblGithubLink.ActiveLinkColor = [System.Drawing.Color]::Red
$lblGithubLink.Add_LinkClicked({
    Start-Process "https://github.com/Hani-K"
})

$lblVersionLink = New-Object $LinkLabelObject
$lblVersionLink.Text = "Version 0.5"
$lblVersionLink.Location = New-Object Drawing.Point(5, 680)
$lblVersionLink.Size = New-Object Drawing.Size(300, 20)
$lblVersionLink.Font = New-Object System.Drawing.Font('Lucida Console',8)
$lblVersionLink.LinkColor = [System.Drawing.Color]::LightGreen
$lblVersionLink.ActiveLinkColor = [System.Drawing.Color]::Red
$lblVersionLink.Add_LinkClicked({
    Start-Process "https://github.com/Hani-K/NetRaft"
})

# Building the form

# Menu Label
$lblMenu = New-Object $LabelObject
$lblMenu.Text = 'Tools:'
$lblMenu.AutoSize = $true
$lblMenu.Location = New-Object System.Drawing.Point(5,28)

# Dropdown
$ddlMenu = New-Object $ComboBoxObject
$ddlMenu.Width = '380'
$ddlMenu.Font = 'Calibri,11'
$ddlMenu.Location = New-Object System.Drawing.Point(55,24)
$ddlMenu.Text = 'Select...'

# Adding tools to the dropdown menu
$pingSweeper = "Ping Sweeper - ping a range of addresses"
$portScanner = "Port Scanner - scan a ports of an address"
$routeTracer = "Route Tracer - Trace route of an address"
$dnsRecordSnagger = "DNS Record Sweeper - Checks for all records"

# Details Label
$lblInitial = New-Object $LabelObject
$lblInitial.Text = 'Select a tool please to continue...'
$lblInitial.AutoSize = $true
$lblInitial.Location = New-Object System.Drawing.Point(5,180)

# Destails
$boxHelp = New-Object $RichTextBoxObject
$boxHelp.Text = 'Dog shit >.<'
$boxHelp.AutoSize = $true
$boxHelp.ClientSize = new-Object System.Drawing.Size(487, 100)
$boxHelp.Location = New-Object System.Drawing.Point(5,60)
$boxHelp.ReadOnly = $true
$boxHelp.Font = New-Object System.Drawing.Font('Calibri',18)
$boxHelp.BackColor = '#959595' #'#ACACAC'
$boxHelp.ForeColor = 'Black' #'#ACACAC'
$boxHelp.ScrollBars = 'None'
$boxHelp.BorderStyle = [System.Windows.Forms.BorderStyle]::None

# Status Box
$boxStatus = New-Object $RichTextBoxObject
$boxStatus.Text = 'Status...'
$boxStatus.AutoSize = $true
$boxStatus.ClientSize = new-Object System.Drawing.Size(487, 320)
$boxStatus.Location = New-Object System.Drawing.Point(5,350)
$boxStatus.ReadOnly = $true
$boxStatus.Font = New-Object System.Drawing.Font('Calibri',12)
$boxStatus.BackColor = 'Black' #'#ACACAC'
$boxStatus.ForeColor = 'Red' #'#ACACAC'
$boxStatus.Multiline = $true
$boxStatus.BorderStyle = [System.Windows.Forms.BorderStyle]::None

# Parameters Label
$lblParameters = New-Object $LabelObject
$lblParameters.Text = 'Parameters:'
$lblParameters.AutoSize = $true
$lblParameters.Location = New-Object System.Drawing.Point(5,180)
$lblParameters.Visible = $false

# Lable - Parameter 1:
$lblParameter1 = New-Object $LabelObject
$lblParameter1.Text = 'Parameter1'
$lblParameter1.AutoSize = $true
$lblParameter1.Location = New-Object System.Drawing.Point(25,200)
$lblParameter1.Font = 'sans,9'
$lblParameter1.ForeColor = 'Black'
$lblParameter1.Visible = $false

# TextBox - Parameter 1:
$boxParameter1 = New-Object $MaskedTextBoxObject
$boxParameter1.Text = 'Input Parameter..'
$boxParameter1.Width = '130'
$boxParameter1.AutoSize = $true
$boxParameter1.Location = New-Object System.Drawing.Point(100,202)
$boxParameter1.Font = 'Calibri,11'
$boxParameter1.ForeColor = 'Black'
$boxParameter1.Enabled = $false
$boxParameter1.Visible = $false


# Lable - Parameter 2:
$lblParameter2 = New-Object $LabelObject
$lblParameter2.Text = 'Parameter2'
$lblParameter2.AutoSize = $true
$lblParameter2.Location = New-Object System.Drawing.Point(25,230)
$lblParameter2.Font = 'Sans,9'
$lblParameter2.ForeColor = 'Black'
$lblParameter2.Visible = $false

# TextBox - Parameter 2:
$boxParameter2 = New-Object $MaskedTextBoxObject
$boxParameter2.Text = 'Input Parameter..'
$boxParameter2.Width = '130'
$boxParameter2.AutoSize = $true
$boxParameter2.Location = New-Object System.Drawing.Point(100,232)
$boxParameter2.Font = 'Calibri,11'
$boxParameter2.ForeColor = 'Black'
$boxParameter2.Enabled = $false
$boxParameter2.Visible = $false

# Action Button
$btnAction = New-Object $ButtonObject
$btnAction.Text = 'Troubleshoot'
$btnAction.AutoSize = $true
$btnAction.Location = New-Object System.Drawing.Point(390,315)
$btnAction.ClientSize = New-Object System.Drawing.Size(100, 30)
$btnAction.BackColor = 'Red'
$btnAction.FlatStyle = 'Flat'
$btnAction.Enabled = $false
$btnAction.Visible = $false
$btnAction.Font = $DefauktBtnFont

# Preset Label
$lblPreset = New-Object $LabelObject
$lblPreset.Text = 'Presets:'
$lblPreset.AutoSize = $true
$lblPreset.Location = New-Object System.Drawing.Point(240,180)
$lblPreset.Visible = $false

# Preset Button1
$btnPreset1 = New-Object $ButtonObject
$btnPreset1.Text = 'Preset 1'
$btnPreset1.AutoSize = $true
$btnPreset1.ClientSize = new-Object System.Drawing.Size(110, 30)
$btnPreset1.Location = New-Object System.Drawing.Point(270,202)
$btnPreset1.FlatStyle = 'Flat'
$btnPreset1.Enabled = $false
$btnPreset1.Visible = $false
$btnPreset1.Font = $DefauktBtnFont

# Preset Button2
$btnPreset2 = New-Object $ButtonObject
$btnPreset2.Text = 'Preset 2'
$btnPreset2.AutoSize = $true
$btnPreset2.ClientSize = new-Object System.Drawing.Size(110, 30)
$btnPreset2.Location = New-Object System.Drawing.Point(270,235)
$btnPreset2.FlatStyle = 'Flat'
$btnPreset2.Enabled = $false
$btnPreset2.Visible = $false

# Preset Button3
$btnPreset3 = New-Object $ButtonObject
$btnPreset3.Text = 'Preset 3'
$btnPreset3.AutoSize = $true
$btnPreset3.ClientSize = new-Object System.Drawing.Size(110, 30)
$btnPreset3.Location = New-Object System.Drawing.Point(385,202)
$btnPreset3.FlatStyle = 'Flat'
$btnPreset3.Enabled = $false
$btnPreset3.Visible = $false

# Preset Button4
$btnPreset4 = New-Object $ButtonObject
$btnPreset4.Text = 'Preset 4'
$btnPreset4.AutoSize = $true
$btnPreset4.ClientSize = new-Object System.Drawing.Size(110, 30)
$btnPreset4.Location = New-Object System.Drawing.Point(385,235)
$btnPreset4.FlatStyle = 'Flat'
$btnPreset4.Enabled = $false
$btnPreset4.Visible = $false

# Save Button
$btnSave = New-Object $ButtonObject
$btnSave.Text = 'Save'
$btnSave.AutoSize = $true
$btnSave.ClientSize = new-Object System.Drawing.Size(100, 30)
$btnSave.Location = New-Object System.Drawing.Point(285,315)
$btnSave.FlatStyle = 'Flat'
$btnSave.BackColor = 'White'
$btnSave.Enabled = $false
$btnSave.Visible = $false

# Abort Button
$btnAbort = New-Object $ButtonObject
$btnAbort.Text = 'ABORT!'
$btnAbort.AutoSize = $true
$btnAbort.ClientSize = New-Object System.Drawing.Size(60, 30)
$btnAbort.Location = New-Object System.Drawing.Point(5,315)
$btnAbort.FlatStyle = 'Flat'
$btnAbort.BackColor = 'White'
$btnAbort.Enabled = $false
$btnAbort.Visible = $false

# Parameters
$global:abortTraceroute = $false

$script:CheckParam1 = "0"
$script:CheckParam2 = "0"
$script:Param1 = "0"
$script:Param2 = "0"
$script:Param3 = 0

# Timers

<#
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1000  # 1000 milliseconds (1 second)
$timer.Add_Tick({    
    # Scroll to the caret
    $boxStatus.ScrollToCaret()
})
$timer.Start()

#>

###############################################################################
# Functions:

# Function to save TextBox content
function saveTextBoxContent {
    param (
        [System.Windows.Forms.RichTextBox]$RichTextBox
    )

    # Create a SaveFileDialog
    $saveFileDialog = New-Object Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $saveFileDialog.Title = "Save File"
    $saveFileDialog.DefaultExt = "txt"

    if ($saveFileDialog.ShowDialog() -eq 'OK') {
        # Save the content of the RichTextBox to the selected file
        $RichTextBox.SaveFile($saveFileDialog.FileName, [System.Windows.Forms.RichTextBoxStreamType]::PlainText)
        Write-Host "`nContent saved to $($saveFileDialog.FileName)"
        $boxStatus.AppendText("`n`r")
        appendColoredLine $boxStatus White "Content saved to $($saveFileDialog.FileName)"
        $boxStatus.ScrollToCaret()
    }
}

function Test-IsIPAddress {
    param (
        [string]$ip
    )

    # Define a regular expression for IPv4 address
    $ipRegex = '^\b(?:\d{1,3}\.){3}\d{1,3}\b$'

    if ($ip -match $ipRegex) {
        Write-Host "True"
        return $true
    } else {
        Write-Host "False"
        return $false
    }
}

####
<# Function to start tools in a background job
function FunctionStarter {
    $menuItem = $ddlMenu.SelectedItem
    $global:job = Start-Job -ScriptBlock {
        if ($menuItem -eq $pingSweeper){
            #pingSweeperForm
        }
        #MyFunction
    } -Name #pingSweeperForm #MyFunction
}

# Function to abort the started job
function Abort-MyFunction {
    if ($global:job -ne $null) {
        Write-Output "Aborting..."
        Stop-Job -Job $global:job
        Remove-Job -Job $global:job
        $global:job = $null
        Write-Output "Function aborted."
    } else {
        Write-Output "Function is not running."
    }
}
#>

####
# DNS 

function dnsRecordSnaggerForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Arial',12,$boldFont)
    appendColoredLine $boxHelp Blue "DNS Record Snagger!"

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',5)
    $boxHelp.AppendText("`n")

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    appendColoredLine $boxHelp Black "This tool will give you the DNS server addresses for all network devices on the system as well as snag all the DNS records available for a target domain."
    
    # Status
    $boxStatus.Text = "DNS Record Snagger is selected - Status: Not Ready!"

    # First Parameter
    $lblParameter1.Visible = $true
    $boxParameter1.Visible = $true
    $boxParameter1.Enabled = $true
    $boxParameter1.ForeColor = 'Gray'
    $boxParameter1.Text = "example.com"
    $boxParameter1.Mask = ''

    # GotFocus event handler
    $boxParameter1.Add_GotFocus({
        if ($This.ForeColor -eq 'Gray') {
            $This.Text = ""
            $This.ForeColor = 'Black'
        }
    })

    $lblParameter1.Text = 'Target:'

    # Second Parameter
    $boxParameter2.Visible = $false
    $lblParameter2.Visible = $false

    # Labels

    $lblPreset.Visible = $false
    
    # Buttons

    ## Save Button
    $btnSave.Enabled = $true
    $btnSave.Visible = $true

    $btnSave.add_Click({
        saveTextBoxContent -RichTextBox $boxStatus
    })

    
    ## Button 1
    $btnPreset1.Visible = $false
       
    ## Button 2
    $btnPreset2.Visible = $false
    
    ## Button 3
    $btnPreset3.Visible = $false
   
    ## Button 4
    $btnPreset4.Visible = $false
    
    ## Action Button
    $btnAction.Visible = $true
    

    ## Creating an event handler with an m-bit to handle against specific conditions
    $boxParameter1.add_TextChanged({
        if ($boxParameter1 -ne '') {
            $script:CheckParam1 = "1"
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam1 = "0"
            $script:CheckParam2 = "1"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $btnAction.add_Click({
        $script:Param1 = $boxParameter1.Text
        dnsRecordSnagger -target "$script:Param1"
    })
    
    # Extras
    $lblInitial.Visible = $false
    $lblParameters.Visible = $true
}

function performDNSLookup {
    param (
        [string]$target,
        [string]$recordType
    )

    try {
        $dnsResults = Resolve-DnsName -Name $target -Type $recordType -ErrorAction Stop
        $output = "DNS Lookup Results for $target ($recordType):`r`n"
        $output += $dnsResults | Format-Table -AutoSize | Out-String
        $output += "`r`n"
        Write-Output $output
        appendColoredLine $boxStatus White "$output"
        $boxStatus.ScrollToCaret()
        #Add-Content -Path $outputFilePath -Value $output
    } catch {
        Write-Error "Error performing DNS lookup: $_"
    }
}

function checkNetworkDNS {
    try {
        $networkDNS = Get-DnsClientServerAddress -ErrorAction Stop
        $output = "DNS server addresses of network devices on this machine:`r`n"
        $output += $networkDNS | Format-Table -AutoSize | Out-String
        $output += "`r`n"
        Write-Output $output
        appendColoredLine $boxStatus White "$output"
        $boxStatus.ScrollToCaret()
        #Add-Content -Path $outputFilePath -Value $output
    } catch {
        Write-Error "Error while checking for Network DNS: $_"
    }
}

function dnsRecordSnagger {
    param (
    [string]$target = "google.com"
    )

    $boxStatus.Clear()
    appendColoredLine $boxStatus Yellow "DNS Record Snagger is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    appendColoredLine $boxStatus White "Preparing..."
    appendColoredLine $boxStatus White "Target: $target"
    $boxStatus.AppendText("`r`n")

    
    # Define supported record types
    $validRecordTypes = @("A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT")

    # Print DNS addresses for all available network devices
    checkNetworkDNS

    # Perform DNS lookups for each record type
    foreach ($recordType in $validRecordTypes) {
        performDNSLookup -target $target -recordType $recordType
    }

    # Save file of the results
    saveTextBoxContent
    
}


####
# Route Tracer

function routeTraceForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Arial',12,$boldFont)
    appendColoredLine $boxHelp Blue "Route Tracer!"

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',5)
    $boxHelp.AppendText("`n")

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    appendColoredLine $boxHelp Black "This tool allows you to trace the route to a server or a domain. You can select the number of hops and timeout limit."
    
    # Status
    $boxStatus.Text = "Route Tracer is selected - Status: Not Ready!"

    # First Parameter
    $lblParameter1.Visible = $true
    $boxParameter1.Visible = $true
    $boxParameter1.Enabled = $true
    $boxParameter1.ForeColor = 'Gray'
    $boxParameter1.Text = "example.com"
    $boxParameter1.Mask = ''

    # GotFocus event handler
    $boxParameter1.Add_GotFocus({
        if ($This.ForeColor -eq 'Gray') {
            $This.Text = ""
            $This.ForeColor = 'Black'
        }
    })

    $lblParameter1.Text = 'Destination:'

    # Second Parameter
    $lblParameter2.Visible = $true
    $boxParameter2.Visible = $true
    $boxParameter2.Enabled = $true
    $boxParameter2.ForeColor = 'Gray'
    $boxParameter2.Text = "3"
    $boxParameter2.Mask = ''

    # GotFocus event handler
    $boxParameter2.Add_GotFocus({
        if ($This.ForeColor -eq 'Gray') {
            $This.Text = ""
            $This.ForeColor = 'Black'
        }
    })

    $lblParameter2.Text = 'Max. Hops:'

    # Labels

    $lblPreset.Visible = $true
    $lblPreset.Text = "Max. Timeout:"

    # Buttons

    ## Save Button
    $btnSave.Enabled = $true
    $btnSave.Visible = $true

    $btnSave.add_Click({
        saveTextBoxContent -RichTextBox $boxStatus
    })

    <#
    ## Abort Button
    $btnAbort.Visible = $true

    $btnAbort.add_Click({
        $global:abortTraceroute = $true
    })
    #>

    ## Button 1
    $btnPreset1.Visible = $true
    $btnPreset1.Enabled = $true
    $btnPreset1.Text = '1 Second'
    $btnPreset1.add_Click({
        if($boxParameter1.Text -ne "") {
            $textLoop1 = $boxParameter1.Text
        }
        $boxParameter1.Text = $textLoop1

        if($boxParameter2.Text -ne "") {
            $textLoop2 = $boxParameter2.Text
        }
        $boxParameter2.Text = $textLoop2
        $script:Param3 = 1000
    })
    
    ## Button 2
    $btnPreset2.Visible = $true
    $btnPreset2.Enabled = $true
    $btnPreset2.Text = '3 Seconds'
    $btnPreset2.add_Click({
        $script:Param3 = 3000
    })

    ## Button 3
    $btnPreset3.Visible = $true
    $btnPreset3.Enabled = $true
    $btnPreset3.Text = '5 Seconds'
    $btnPreset3.add_Click({
        $script:Param3 = 5000
    })

    ## Button 4
    $btnPreset4.Visible = $true
    $btnPreset4.Enabled = $true
    $btnPreset4.Text = '10 Seconds'
    $btnPreset4.add_Click({
        $script:Param3 = 10000
    })

    ## Action Button
    $btnAction.Visible = $true
    

    ## Creating an event handler with an m-bit to handle against specific conditions
    $boxParameter1.add_TextChanged({
        if ($boxParameter1 -ne '') {
            $script:CheckParam1 = "1"
        } else {
            $script:CheckParam1 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $boxParameter2.add_TextChanged({
        if ($boxParameter2 -ne '') {
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam2 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
    })

    $btnAction.add_Click({
        $script:Param1 = $boxParameter1.Text 
        $script:Param2 = [int]$boxParameter2.Text
        routeTracerfunction -Destination "$script:Param1" -MaxHops $script:Param2 -TimeOut $script:Param3
    })
    
    # Extras
    $lblInitial.Visible = $false
    $lblParameters.Visible = $true
}

function routeTracerfunction {
    param (
        [string]$Destination,
        [int32]$MaxHops = 5,
        [int32]$TimeOut = 10000
    )

    $boxStatus.Clear()
    appendColoredLine $boxStatus Yellow "RouteTracer is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    appendColoredLine $boxStatus White "Preparing..."
    appendColoredLine $boxStatus White "Destination: $Destination"
    appendColoredLine $boxStatus White "MaxHops: $MaxHops"
    appendColoredLine $boxStatus White "TimeOut: $TimeOut"
    $boxStatus.AppendText("`r`n")
 

    $pingCommand = "Test-Connection"
    $pingArgs = @{
        "ComputerName" = $Destination
        "Count" = 1
        "ErrorAction" = "SilentlyContinue"
    }

    $tracerouteCommand = "tracert"

    Write-Host "Performing traceroute to $Destination..."
    appendColoredLine $boxStatus White "Performing traceroute to $Destination..."

    try {
        $pingResult = & $pingCommand @pingArgs
        if ($null -eq $pingResult) {
            throw "Destination host not reachable."
        }

        $tracerouteResult = & $tracerouteCommand -h $MaxHops -w $TimeOut $Destination

        # Display the traceroute result using Write-Host
        Write-Host "`nTraceroute result:`n"
        Write-Host $tracerouteResult
        $boxStatus.AppendText("`n`r")
        appendColoredLine $boxStatus Yellow "Traceroute result:"
        $boxStatus.AppendText("`n`r")
        appendColoredLine $boxStatus White "$tracerouteResult"

    }
    catch {
        Write-Host "Error: $_"
    }

    
}


####
# portScannerForm
function portScannerForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Arial',12,$boldFont)
    appendColoredLine $boxHelp Blue "PortScanner!"

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',5)
    $boxHelp.AppendText("`n")

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    appendColoredLine $boxHelp Black "This tool can scan for open or closed ports against a specific domain or a host. You can scan multiple ports by separating them with ', '."
    
    # Status
    $boxStatus.Text = "PortScanner is selected - Status: Not Ready!"

    # First Parameter
    $lblParameter1.Visible = $true
    $boxParameter1.Visible = $true
    $boxParameter1.Enabled = $true
    $boxParameter1.ForeColor = 'Gray'
    $boxParameter1.Text = "80,443,3389"
    $boxParameter1.Mask = ''

    # GotFocus event handler
    $boxParameter1.Add_GotFocus({
        if ($This.ForeColor -eq 'Gray') {
            $This.Text = ""
            $This.ForeColor = 'Black'
        }
    })

    $lblParameter1.Text = 'Ports:'

    # Second Parameter
    $lblParameter2.Visible = $true
    $boxParameter2.Visible = $true
    $boxParameter2.Enabled = $true
    $boxParameter2.ForeColor = 'Gray'
    $boxParameter2.Text = '127.0.0.1'
    $boxParameter2.Mask = ''

    # GotFocus event handler
    $boxParameter2.Add_GotFocus({
        if ($This.ForeColor -eq 'Gray') {
            $This.Text = ""
            $This.ForeColor = 'Black'
        }
    })

    $lblParameter2.Text = 'Domain:'

    # Labels

    $lblPreset.Visible = $true


    # Buttons

    ## Save Button
    $btnSave.Enabled = $true
    $btnSave.Visible = $true

    $btnSave.add_Click({
        saveTextBoxContent -RichTextBox $boxStatus
    })

    ## Abort Button
    #$btnAbort.Visible = $true

    #$btnAbort.add_Click({
    #    Abort-MyFunction
    #})

    ## Button 1
    $btnPreset1.Visible = $true
    $btnPreset1.Enabled = $true
    $btnPreset1.Text = 'HTTP/HTTPS'
    $btnPreset1.add_Click({
        $boxParameter1.Text = "80,443"
        $boxParameter2.Text = "localhost"
    })
    
    ## Button 2
    $btnPreset2.Visible = $true
    $btnPreset2.Enabled = $true
    $btnPreset2.Text = 'DNS'
    $btnPreset2.add_Click({
        $boxParameter1.Text = "53,5533,5353"
        $boxParameter2.Text = "localhost"
    })

    ## Button 3
    $btnPreset3.Visible = $true
    $btnPreset3.Enabled = $true
    $btnPreset3.Text = 'Wireguard'
    $btnPreset3.add_Click({
        $boxParameter1.Text = "51820"
        $boxParameter2.Text = "localhost"
    })

    ## Button 4
    $btnPreset4.Visible = $true
    $btnPreset4.Enabled = $true
    $btnPreset4.Text = 'SFTP/SSH'
    $btnPreset4.add_Click({
        $boxParameter1.Text = "22,21"
        $boxParameter2.Text = "localhost"
    })

    ## Action Button
    $btnAction.Visible = $true
    

    ## Creating an event handler with an m-bit to handle against specific conditions
    $boxParameter1.add_TextChanged({
        if ($boxParameter1 -ne '') {
            $script:CheckParam1 = "1"
        } else {
            $script:CheckParam1 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $boxParameter2.add_TextChanged({
        if ($boxParameter2 -ne '') {
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam2 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
    })

    $btnAction.add_Click({
        $script:Param1 = $boxParameter1.Text -split ',' | ForEach-Object { [int]$_ }
        $script:Param2 = $boxParameter2.Text
        portScannerFunction -ports $script:Param1 -hostname $script:Param2 -timeout 1500
    })
    
    # Extras
    $lblInitial.Visible = $false
    $lblParameters.Visible = $true
}

##
function portScannerFunction {
    param(
        [int[]]$ports=80,
        [string]$hostname='yahoo.com',
        [int]$timeout=1000
    )

    $boxStatus.Clear()
    appendColoredLine $boxStatus Yellow "PingScanner is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    appendColoredLine $boxStatus White "Preparing..."
    appendColoredLine $boxStatus White "Ports: $ports"
    appendColoredLine $boxStatus White "Hostname: $hostname"
    appendColoredLine $boxStatus White "Timeout: $timeout"
    $boxStatus.AppendText("`r`n")

    $opened = @()
    $closed = @()

    appendColoredLine $boxStatus Yellow "Scanning Started!"
    appendColoredLine $boxStatus LightGreen "`nOpen Ports"

    foreach ($port in $ports){
        $clientTCP = New-Object System.Net.Sockets.TcpClient
        try{
            $clientTCP.ConnectAsync($hostname,$port).Wait($timeout)
            if ($clientTCP.Connected) {
                Write-Output "Open $port of $ports"
                $opened += "$port"
            } else {
                Write-Output "close $port of $ports"
                $closed += "$port"
            }
        } catch {
            Write-Output "close $port of $ports"
            $closed += $port
        } finally {
            if ($clientTCP -ne "") {
                $clientTCP.Close()
            }
        }
    }

    $scannedOpenPorts = $($opened -join "`n")
    if ($scannedOpenPorts -ne ""){
        $openPorts = $scannedOpenPorts
    } else {
        $openPorts = "Null"
    }

    $scannedClosePorts = $($closed -join "`n")
    if ($scannedClosePorts -ne ""){
        $closePorts = $scannedClosePorts
    } else {
        $closePorts = "Null"
    }
    
    Write-Host "`n`nOpened Ports:`n$openPorts" -ForegroundColor Green
    Write-Host "`n`nClosed Ports:`n$closePorts" -ForegroundColor Red

    appendColoredLine $boxStatus White "$openPorts"
    appendColoredLine $boxStatus Red "`n`nClose Ports"
    appendColoredLine $boxStatus White "$closePorts"

}

####

# PingSweeper Form
function pingSweeperForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Arial',12,$boldFont)
    appendColoredLine $boxHelp Blue "PingSweeper!"

    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',5)
    $boxHelp.AppendText("`n")
    
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    appendColoredLine $boxHelp Black "This tool pings a rang of addersses selected. Type the range of IP addresses you would like to ping for. The tool will then determine the reachablity of each address and save the report. You can select one of the preset ranges for quick RFC1918 troubleshooting."
    
    # Status
    $boxStatus.Text = "PingSweeper is selected - Status: Not Ready!"

    # First Parameter
    $lblParameter1.Visible = $true
    $boxParameter1.Visible = $true
    $boxParameter1.MaxLength = '15'
    $boxParameter1.Mask = '000\.000\.000\.000'
    $boxParameter1.Enabled = $true

    $lblParameter1.Text = 'Starting IP:'

    # Second Parameter
    $lblParameter2.Visible = $true
    $boxParameter2.Visible = $true
    $boxParameter2.MaxLength = '15'
    $boxParameter2.Mask = '000\.000\.000\.000'
    $boxParameter2.Enabled = $true

    $lblParameter2.Text = ' Ending IP:'


    # Labels

    $lblPreset.Visible = $true

    # Buttons

    ## Save Button
    $btnSave.Enabled = $true
    $btnSave.Visible = $true

    $btnSave.add_Click({
        saveTextBoxContent -RichTextBox $boxStatus
    })

    ## Abort Button
    #$btnAbort.Visible = $true

    #$btnAbort.add_Click({
    #    Abort-MyFunction
    #})
    
    ## Button 1
    $btnPreset1.Text = '10.0.10.0/24'
    $btnPreset1.Visible = $true
    $btnPreset1.Enabled = $true
    $btnPreset1.add_Click({
        $boxParameter1.Text = "10 .0  .10 .0"
        $boxParameter2.Text = "10 .0  .10 .254"

        $script:Param1 = $boxParameter1.Text -replace '\s', ''
        $script:Param2 = $boxParameter2.Text -replace '\s', ''
    })
    
    ## Button 2
    $btnPreset2.Text = '192.168.0.0/24'
    $btnPreset2.Visible = $true
    $btnPreset2.Enabled = $true
    $btnPreset2.add_Click({
        $boxParameter1.Text = "192.168.0  .0  "
        $boxParameter2.Text = "192.168.0  .254"

        $script:Param1 = $boxParameter1.Text -replace '\s', ''
        $script:Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Button 3
    $btnPreset3.Text = '192.168.1.0/24'
    $btnPreset3.Visible = $true
    $btnPreset3.Enabled = $true
    $btnPreset3.add_Click({
        $boxParameter1.Text = "192.168.1  .0  "
        $boxParameter2.Text = "192.168.1  .254"

        $script:Param1 = $boxParameter1.Text -replace '\s', ''
        $script:Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Button 4
    $btnPreset4.Text = '172.16.16.0/24'
    $btnPreset4.Visible = $true
    $btnPreset4.Enabled = $true
    $btnPreset4.add_Click({
        $boxParameter1.Text = "172.16 .16 .0  "
        $boxParameter2.Text = "172.16 .16 .254"

        $script:Param1 = $boxParameter1.Text -replace '\s', ''
        $script:Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Action Button
    $btnAction.Visible = $true
    

    ## Creating an event handler with an m-bit to handle against specific conditions
    $boxParameter1.add_TextChanged({
        $script:Param1 = $boxParameter1.Text -replace '\s', ""
        $IP1 = Test-IsIPAddress -ip "$script:Param1"
        if ($IP1) {
            $script:CheckParam1 = "1"
        } else {
            $script:CheckParam1 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $boxParameter2.add_TextChanged({
        $script:Param2 = $boxParameter2.Text -replace '\s', ""
        $IP2 = Test-IsIPAddress -ip "$script:Param2"
        if ($IP2) {
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam2 = "0"
            }
        pingActionEventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
    })

    $btnAction.add_Click({
        $script:Param1 = $boxParameter1.Text -replace '\s', ""
        $script:Param2 = $boxParameter2.Text -replace '\s', ""
        pingSweeperFunction -StartIP $script:Param1 -endIP $script:Param2
    })
    
    # Extras
    $lblInitial.Visible = $false
    $lblParameters.Visible = $true
}

function pingActionEventHandler {
    param(
        [string]$CheckParam1,
        [string]$CheckParam2
    )
    
    #Write-Host "CheckParams: $CheckParam1, $CheckParam2"
    if ($CheckParam1 -eq "1" -and $CheckParam2 -eq "1") {
        #Write-Host "Action is Green!"
        $btnAction.BackColor = 'LightGreen'
        $btnAction.Enabled = $true
        $boxStatus.ForeColor = 'LightGreen'
        $btnAbort.Enabled = $true
        $btnAbort.BackColor = 'Red'

        $menuItem = $ddlMenu.SelectedItem
        if ($menuItem -eq $pingSweeper){
            $boxStatus.Text = "PingSweeper is selected - Status: Ready."
        } elseif ($menuItem -eq $portScanner){
            $boxStatus.Text = "PortScanner is selected - Status: Ready."
        } elseif ($menuItem -eq $routeTracer){
            $boxStatus.Text = "Route Tracer is selected - Status: Ready."
        } elseif ($menuItem -eq $dnsRecordSnagger){
            $boxStatus.Text = "DNS Record Snagger is selected - Status: Ready."
        }

    } else {
        #Write-Host "Action is Red!"
        $btnAction.BackColor = 'Red'
        $btnAction.Enabled = $false
        $btnAbort.Enabled = $false
        $btnAbort.BackColor = 'White'
        $boxStatus.ForeColor = 'Red'

        $menuItem = $ddlMenu.SelectedItem
        if ($menuItem -eq $pingSweeper){
            $boxStatus.Text = "PingSweeper is selected - Status: Not Ready."
        } elseif ($menuItem -eq $portScanner){
            $boxStatus.Text = "PortScanner is selected - Status: Not Ready."
        } elseif ($menuItem -eq $routeTracer){
            $boxStatus.Text = "Route Tracer is selected - Status: Not Ready."
        } elseif ($menuItem -eq $dnsRecordSnagger){
            $boxStatus.Text = "DNS Record Snagger is selected - Status: Not Ready."
        }
    }
}

function pingSweeperFunction{
    param(
        [string]$StartIP,
        [string]$endIP
    )

    # Logging
    $boxStatus.Clear()
    appendColoredLine $boxStatus Yellow "PingSweeper is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    appendColoredLine $boxStatus White "Preparing..."
    appendColoredLine $boxStatus White "IP Addresses: $StartIP to $endIP"
    $boxStatus.AppendText("`r`n")

    $startIPSplit = $StartIP -split '\.'
    $startIP4thOctet = $startIPSplit[-1]
    $startIP_Curated = [int]$startIP4thOctet
    
    $endIPSplit = $endIP -split '\.'
    $endIP4thOctet = $endIPSplit[-1]
    $endIP_Curated = [int]$endIP4thOctet

    $IP_subnet = ($startIPSplit[0..2] -join '.') + "."


    Write-Host "Subnet:$IP_subnet"
    
    if ($startIP_Curated -lt $endIP_Curated){
        $reachable = @()
        $not_reachable = @()

        appendColoredLine $boxStatus Yellow "Sweeping Started!"
        appendColoredLine $boxStatus LightGreen "`nReachable Hosts"
        # Loop through the range and ping sweep
        for ($i = $startIP_Curated; $i -le $endIP_Curated; $i++) {
            $currentIP = $IP_subnet + $i
            $result = Test-Connection -ComputerName $currentIP -Count 1 -ErrorAction SilentlyContinue

            if ($result) {
                $reachable += $currentIP
            } else {
                $not_reachable += $currentIP
            }
        }
        Write-Host "`n`nReachable Hosts:`n$($reachable -join "`n")" -ForegroundColor Green
        Write-Host "`n`nNone Reachable Hosts:`n$($not_reachable -join "`n")" -ForegroundColor Red
        appendColoredLine $boxStatus White "$($reachable -join "`n")"
        appendColoredLine $boxStatus Red "`n`nNone Reachable Hosts"
        appendColoredLine $boxStatus White "$($not_reachable -join "`n")"
    } else {
        $boxStatus.Clear()
        appendColoredLine $boxStatus Red "The Start IP cannot be higher than the End IP."
        Write-Host "The Start IP cannot be higher than the End IP."
    }
   
}

###############################################################################

# Loading tools to the dropdown
$toolsMenu = @($pingSweeper,$portScanner,$routeTracer,$dnsRecordSnagger)
ForEach-Object {
    $ddlMenu.Items.AddRange($toolsMenu)
}

# Adding the objects to the form
$AppForm.Controls.AddRange(@($lblMenu,$ddlMenu,$lblInitial,$boxHelp,$boxStatus,$lblParameter1,$boxParameter1,$lblParameter2,$boxParameter2,$lblParameters,$btnAction,$lblPreset,$btnPreset1,$btnPreset2,$btnPreset3,$btnPreset4,$btnSave,$btnAbort,$lblGithubLink,$lblVersionLink))

## Menu functionality
function GetMenuItemObjects{
    $menuItem = $ddlMenu.SelectedItem

    switch ($menuItem) {
        $pingSweeper {
            pingSweeperForm
        }
        $portScanner {
            portScannerForm
        }
        $routeTracer {
            routeTraceForm
        }
        $dnsRecordSnagger {
            dnsRecordSnaggerForm
        }
        '5' {
            Write-Host "Empty for now!"
        }
        default {
            Write-Host "Selector!"
        }
    }
}

# Event handler for the drop down menu
$ddlMenu.Add_SelectionChangeCommitted({
    $btnAction.BackColor = 'Red'
    $btnAction.Enabled = $false
    $btnAbort.Enabled = $false
    $btnAbort.BackColor = 'White'
    $boxStatus.ForeColor = 'Red'

    $menuItem = $ddlMenu.SelectedItem
    if ($menuItem -eq $pingSweeper){
        $boxStatus.Text = "PingSweeper is selected - Status: Not Ready."
    } elseif ($menuItem -eq $portScanner){
        $boxStatus.Text = "PortScanner is selected - Status: Not Ready."
    }

})

function appendColoredLine {
    param( 
        [Parameter(Mandatory = $true, Position = 0)]
        [System.Windows.Forms.RichTextBox]$box,
        [Parameter(Mandatory = $true, Position = 1)]
        [System.Drawing.Color]$color,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$text
    )
    $box.SelectionStart = $box.TextLength
    $box.SelectionLength = 0
    $box.SelectionColor = $color
    $box.AppendText($text)
    $box.AppendText([Environment]::NewLine)
}

function welcome {
    $boxHelp.Clear()
    $boxHelp.BackColor = 'Black'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',16)
    $boxHelp.SelectionAlignment = 'Center'
    appendColoredLine $boxHelp LightGreen "Welcome To NetRaft!"
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',12)
    appendColoredLine $boxHelp LightGreen "The muli-functional network troubleshooter!"
    #$boxHelp.AppendText("`r`n")
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',12)
    appendColoredLine $boxHelp Red "Select a tool and begin trouble-shooting! ;)"

}


function StartingPoint {
    welcome
    ## Add functions to controls
    $ddlMenu.Add_SelectedIndexChanged({GetMenuItemObjects})

    # Show Form
    $AppForm.ShowDialog()

    # Garbage
    $AppForm.Dispose()
}

StartingPoint




#########################################################
#
### ARCHIVED
#
#############

        # GotFocus event handler
    #$boxParameter1.Add_GotFocus({
    #    if ($This.ForeColor -eq 'Gray') {
    #        $This.Text = ""
    #        $This.ForeColor = 'Black'
    #    }
    #})