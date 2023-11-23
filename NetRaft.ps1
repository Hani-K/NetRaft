Add-Type -AssemblyName System.Windows.Forms

$FormObject      = [System.Windows.Forms.Form]
$LabelObject     = [System.Windows.Forms.Label]
$ComboBoxObject  = [System.Windows.Forms.ComboBox]
$ButtonObject    = [System.Windows.Forms.Button]
$TextBoxObject = [System.Windows.Forms.TextBox]
$RichTextBoxObject = [Windows.Forms.RichTextBox]
$MaskedTextBoxObject = [System.Windows.Forms.MaskedTextBox]
$ButtonObject = [System.Windows.Forms.Button]

$DefaultFont = 'Calibri,10'

# Setup base form
$AppForm = New-Object $FormObject
$AppForm.ClientSize = '1175,1500'
$AppForm.Text = 'NetRaft - Network Troubleshooter'
$AppForm.BackColor = '#ffffff'
$AppForm.Font = $DefaultFont
$AppForm.FormBorderStyle = "FixedSingle"
$AppForm.StartPosition = "CenterScreen"

# Building the form

# Menu Label
$lblMenu = New-Object $LabelObject
$lblMenu.Text = 'Tools:'
$lblMenu.AutoSize = $true
$lblMenu.Location = New-Object System.Drawing.Point(20,28)

# Dropdown
$ddlMenu = New-Object $ComboBoxObject
$ddlMenu.Width = '1000'
$ddlMenu.Font = 'Calibri,20'
$ddlMenu.Location = New-Object System.Drawing.Point(125,25)
$ddlMenu.Text = 'Select...'

# Adding tools to the dropdown menu
$pingSweeper = "Ping Sweeper - ping a range of addresses"
$portScanner = "Port Scanner - scan a ports of an address"
$routeTracer = "Route Tracer - Trace route of an address"
$dnsRecordSweeper = "DNS Record Sweeper - Checks for all records"

# Details Label
$lblInitial = New-Object $LabelObject
$lblInitial.Text = 'Select a tool please to continue...'
$lblInitial.AutoSize = $true
$lblInitial.Location = New-Object System.Drawing.Point(20,280)

# Destails
$boxHelp = New-Object $RichTextBoxObject
$boxHelp.Text = 'Dog shit >.<'
$boxHelp.AutoSize = $true
$boxHelp.ClientSize = new-Object System.Drawing.Size(1078, 175)
$boxHelp.Location = New-Object System.Drawing.Point(45,80)
$boxHelp.ReadOnly = $true
$boxHelp.Font = New-Object System.Drawing.Font('Calibri',18)
$boxHelp.BackColor = '#959595' #'#ACACAC'
$boxHelp.ForeColor = 'Black' #'#ACACAC'
$boxHelp.ScrollBars = 'None'

# Status Box
$boxStatus = New-Object $RichTextBoxObject
$boxStatus.Text = 'Status...'
$boxStatus.AutoSize = $true
$boxStatus.ClientSize = new-Object System.Drawing.Size(1125, 850)
$boxStatus.Location = New-Object System.Drawing.Point(25,500)
$boxStatus.ReadOnly = $true
$boxStatus.Font = New-Object System.Drawing.Font('Calibri',18)
$boxStatus.BackColor = 'Black' #'#ACACAC'
$boxStatus.ForeColor = 'Red' #'#ACACAC'
$boxStatus.Multiline = $true

# Parameters Label
$lblParameters = New-Object $LabelObject
$lblParameters.Text = 'Parameters:'
$lblParameters.AutoSize = $true
$lblParameters.Location = New-Object System.Drawing.Point(20,280)
$lblParameters.Visible = $false

# Lable - Parameter 1:
$lblParameter1 = New-Object $LabelObject
$lblParameter1.Text = 'Parameter1'
$lblParameter1.AutoSize = $true
$lblParameter1.Location = New-Object System.Drawing.Point(125,320)
$lblParameter1.Font = 'Sans,8'
$lblParameter1.ForeColor = 'Black'
$lblParameter1.Visible = $false

# TextBox - Parameter 1:
$boxParameter1 = New-Object $MaskedTextBoxObject
$boxParameter1.Text = 'Input Parameter..'
$boxParameter1.Width = '175'
$boxParameter1.AutoSize = $true
$boxParameter1.Location = New-Object System.Drawing.Point(250,325)
$boxParameter1.Font = 'Sans,10'
$boxParameter1.ForeColor = 'Black'
$boxParameter1.Enabled = $false
$boxParameter1.Visible = $false


# Lable - Parameter 2:
$lblParameter2 = New-Object $LabelObject
$lblParameter2.Text = 'Parameter2'
$lblParameter2.AutoSize = $true
$lblParameter2.Location = New-Object System.Drawing.Point(125,390)
$lblParameter2.Font = 'Sans,8'
$lblParameter2.ForeColor = 'Black'
$lblParameter2.Visible = $false

# TextBox - Parameter 2:
$boxParameter2 = New-Object $MaskedTextBoxObject
$boxParameter2.Text = 'Input Parameter..'
$boxParameter2.Width = '175'
$boxParameter2.AutoSize = $true
$boxParameter2.Location = New-Object System.Drawing.Point(250,395)
$boxParameter2.Font = 'Sans,10'
$boxParameter2.ForeColor = 'Black'
$boxParameter2.Enabled = $false
$boxParameter2.Visible = $false

# Action Button
$btnAction = New-Object $ButtonObject
$btnAction.Text = 'Troubleshoot'
$btnAction.AutoSize = $true
$btnAction.Location = New-Object System.Drawing.Point(1000,450)
$btnAction.BackColor = 'Red'
$btnAction.FlatStyle = 'Flat'
$btnAction.Enabled = $false
$btnAction.Visible = $false

# Preset Label
$lblPreset = New-Object $LabelObject
$lblPreset.Text = 'Presets:'
$lblPreset.AutoSize = $true
$lblPreset.Location = New-Object System.Drawing.Point(520,280)
$lblPreset.Visible = $false

# Preset Button1
$btnPreset1 = New-Object $ButtonObject
$btnPreset1.Text = 'Preset 1'
$btnPreset1.AutoSize = $true
$btnPreset1.ClientSize = new-Object System.Drawing.Size(170, 40)
$btnPreset1.Location = New-Object System.Drawing.Point(780,395)
$btnPreset1.FlatStyle = 'Flat'
$btnPreset1.Enabled = $false
$btnPreset1.Visible = $false

# Preset Button2
$btnPreset2 = New-Object $ButtonObject
$btnPreset2.Text = 'Preset 2'
$btnPreset2.AutoSize = $true
$btnPreset2.ClientSize = new-Object System.Drawing.Size(170, 40)
$btnPreset2.Location = New-Object System.Drawing.Point(780,325)
$btnPreset2.FlatStyle = 'Flat'
$btnPreset2.Enabled = $false
$btnPreset2.Visible = $false

# Preset Button3
$btnPreset3 = New-Object $ButtonObject
$btnPreset3.Text = 'Preset 3'
$btnPreset3.AutoSize = $true
$btnPreset3.ClientSize = new-Object System.Drawing.Size(170, 40)
$btnPreset3.Location = New-Object System.Drawing.Point(600,325)
$btnPreset3.FlatStyle = 'Flat'
$btnPreset3.Enabled = $false
$btnPreset3.Visible = $false

# Preset Button4
$btnPreset4 = New-Object $ButtonObject
$btnPreset4.Text = 'Preset 4'
$btnPreset4.AutoSize = $true
$btnPreset4.ClientSize = new-Object System.Drawing.Size(170, 40)
$btnPreset4.Location = New-Object System.Drawing.Point(600,395)
$btnPreset4.FlatStyle = 'Flat'
$btnPreset4.Enabled = $false
$btnPreset4.Visible = $false

# Save Button
$btnSave = New-Object $ButtonObject
$btnSave.Text = 'Save'
$btnSave.AutoSize = $true
$btnSave.ClientSize = new-Object System.Drawing.Size(150, 40)
$btnSave.Location = New-Object System.Drawing.Point(1000,395)
$btnSave.FlatStyle = 'Flat'
$btnSave.BackColor = 'White'
$btnSave.Enabled = $false
$btnSave.Visible = $false

# Abort Button
$btnAbort = New-Object $ButtonObject
$btnAbort.Text = 'Abort'
$btnAbort.AutoSize = $true
$btnAbort.ClientSize = new-Object System.Drawing.Size(150, 40)
$btnAbort.Location = New-Object System.Drawing.Point(1000,340)
$btnAbort.FlatStyle = 'Flat'
$btnAbort.BackColor = 'White'
$btnAbort.Enabled = $false
$btnAbort.Visible = $false


# Parameters

$script:CheckParam1 = "0"
$script:CheckParam2 = "0"

###############################################################################
# Functions:

# Function to save TextBox content
function Save-TextBoxContent {
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
        Write-Host "Content saved to $($saveFileDialog.FileName)"
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
# portScannerForm
function portScannerForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',12)
    Append-ColoredLine $boxHelp DarkGreen "PortScanner!"
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    Append-ColoredLine $boxHelp Black "This tool can scan for open or closed ports against a specific domain or a host."
    Append-ColoredLine $boxHelp Black "You can scan multiple ports by separating them with ', '."
    
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
        Save-TextBoxContent -RichTextBox $boxStatus
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
        $boxParameter1.Text = '80'
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
        PingAction-EventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $boxParameter2.add_TextChanged({
        if ($boxParameter2 -ne '') {
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam2 = "0"
            }
        PingAction-EventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
    })

    $btnAction.add_Click({
        $Param1 = $boxParameter1.Text -split ',' | ForEach-Object { [int]$_ }
        $Param1_ = $($Param1 -join ',')
        $Param2 = $boxParameter2.Text
        #Write-Host "Action= $Param1 - $Param1_ - $Param2"
        #portScannerFunction2 -ports $Param1 -domain $Param2
        portScannerFunction -ports $Param1 -hostname $Param2 -timeout 1500
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
    Append-ColoredLine $boxStatus Yellow "PingScanner is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    Append-ColoredLine $boxStatus White "Preparing..."
    Append-ColoredLine $boxStatus White "Ports: $ports"
    Append-ColoredLine $boxStatus White "Hostname: $hostname"
    Append-ColoredLine $boxStatus White "Timeout: $timeout"
    $boxStatus.AppendText("`r`n")

    $opened = @()
    $closed = @()

    Append-ColoredLine $boxStatus Yellow "Scanning Started!"
    Append-ColoredLine $boxStatus LightGreen "`nOpen Ports"

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
            if ($clientTCP -ne $null) {
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

    Append-ColoredLine $boxStatus White "$openPorts"
    Append-ColoredLine $boxStatus Red "`n`nClose Ports"
    Append-ColoredLine $boxStatus White "$closePorts"

}

####

# PingSweeper Form
function pingSweeperForm{
    # Details
    $boxHelp.Clear()
    $boxHelp.BackColor = 'LightGray'
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',12)
    Append-ColoredLine $boxHelp DarkGreen "PingSweeper!"
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    $boxHelp.SelectionAlignment = 'Left'
    Append-ColoredLine $boxHelp Black "This tool pings a rang of addersses selected. Type the range of IP addresses you would like to ping for. The tool will then determine the reachablity of each address and save the report."
    Append-ColoredLine $boxHelp Black "You can select one of the preset ranges for quick RFC1918 troubleshooting."
    
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

    $lblParameter2.Text = 'Ending IP:'


    # Labels

    $lblPreset.Visible = $true

    # Buttons

    ## Save Button
    $btnSave.Enabled = $true
    $btnSave.Visible = $true

    $btnSave.add_Click({
        Save-TextBoxContent -RichTextBox $boxStatus
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

        $Param1 = $boxParameter1.Text -replace '\s', ''
        $Param2 = $boxParameter2.Text -replace '\s', ''
    })
    
    ## Button 2
    $btnPreset2.Text = '192.168.0.0/24'
    $btnPreset2.Visible = $true
    $btnPreset2.Enabled = $true
    $btnPreset2.add_Click({
        $boxParameter1.Text = "192.168.0  .0  "
        $boxParameter2.Text = "192.168.0  .254"

        $Param1 = $boxParameter1.Text -replace '\s', ''
        $Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Button 3
    $btnPreset3.Text = '192.168.1.0/24'
    $btnPreset3.Visible = $true
    $btnPreset3.Enabled = $true
    $btnPreset3.add_Click({
        $boxParameter1.Text = "192.168.1  .0  "
        $boxParameter2.Text = "192.168.1  .254"

        $Param1 = $boxParameter1.Text -replace '\s', ''
        $Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Button 4
    $btnPreset4.Text = '172.16.16.0/24'
    $btnPreset4.Visible = $true
    $btnPreset4.Enabled = $true
    $btnPreset4.add_Click({
        $boxParameter1.Text = "172.16 .16 .0  "
        $boxParameter2.Text = "172.16 .16 .254"

        $Param1 = $boxParameter1.Text -replace '\s', ''
        $Param2 = $boxParameter2.Text -replace '\s', ''
    })

    ## Action Button
    $btnAction.Visible = $true
    

    ## Creating an event handler with an m-bit to handle against specific conditions
    $boxParameter1.add_TextChanged({
        $Param1 = $boxParameter1.Text -replace '\s', ""
        $IP1 = Test-IsIPAddress -ip "$param1"
        if ($IP1) {
            $script:CheckParam1 = "1"
        } else {
            $script:CheckParam1 = "0"
            }
        PingAction-EventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
     })

    $boxParameter2.add_TextChanged({
        $Param2 = $boxParameter2.Text -replace '\s', ""
        $IP2 = Test-IsIPAddress -ip "$param2"
        if ($IP2) {
            $script:CheckParam2 = "1"
        } else {
            $script:CheckParam2 = "0"
            }
        PingAction-EventHandler -CheckParam1 $script:CheckParam1 -CheckParam2 $script:CheckParam2
    })

    $btnAction.add_Click({
        $Param1 = $boxParameter1.Text -replace '\s', ""
        $Param2 = $boxParameter2.Text -replace '\s', ""
        #Write-Host "$Param1, $Param2"
        pingSweeperFunction -StartIP $Param1 -endIP $Param2
    })
    
    # Extras
    $lblInitial.Visible = $false
    $lblParameters.Visible = $true
}

function PingAction-EventHandler {
    param(
        [string]$CheckParam1,
        [string]$CheckParam2
    )
    
    Write-Host "CheckParams: $CheckParam1, $CheckParam2"
    if ($CheckParam1 -eq "1" -and $CheckParam2 -eq "1") {
        Write-Host "Action is Green!"
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
        }

    } else {
        Write-Host "Action is Red!"
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
    }
}

function pingSweeperFunction{
    param(
        [string]$StartIP,
        [string]$endIP
    )

    # Logging
    $boxStatus.Clear()
    Append-ColoredLine $boxStatus Yellow "PingSweeper is selected - Status: Running."
    $boxStatus.AppendText("`r`n")
    Append-ColoredLine $boxStatus White "Preparing..."
    Append-ColoredLine $boxStatus White "IP Addresses: $StartIP to $endIP"
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

        Append-ColoredLine $boxStatus Yellow "Sweeping Started!"
        Append-ColoredLine $boxStatus LightGreen "`nReachable Hosts"
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
        Append-ColoredLine $boxStatus White "$($reachable -join '`n')"
        Append-ColoredLine $boxStatus Red "`n`nNone Reachable Hosts"
        Append-ColoredLine $boxStatus White "$($not_reachable -join "`n")"
    } else {
        $boxStatus.Clear()
        Append-ColoredLine $boxStatus Red "The Start IP cannot be higher than the End IP."
        Write-Host "The Start IP cannot be higher than the End IP."
    }
   
}

###############################################################################

# Loading tools to the dropdown
$toolsMenu = @($pingSweeper,$portScanner,$routeTracer,$dnsRecordSweeper)
ForEach-Object {
    $ddlMenu.Items.AddRange($toolsMenu)
}

# Adding the objects to the form
$AppForm.Controls.AddRange(@($lblMenu,$ddlMenu,$lblInitial,$boxHelp,$boxStatus,$lblParameter1,$boxParameter1,$lblParameter2,$boxParameter2,$lblParameters,$btnAction,$lblPreset,$btnPreset1,$btnPreset2,$btnPreset3,$btnPreset4,$btnSave,$btnAbort))

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
        '3' {
            sweep -StartIP 0 -endIP 255 -subnet "172.17.17."
            break
        }
        '4' {
            sweep -StartIP 0 -endIP 255 -subnet "192.168.1."
            break
        }
        '5' {
            sweep -StartIP 0 -endIP 255 -subnet "192.168.0."
            break
        }
        default {
            Write-Host "Invalid selection. Please enter 1, 2, or 3."
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

function Append-ColoredLine {
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
    Append-ColoredLine $boxHelp LightGreen "Welcome To NetRaft!"
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    Append-ColoredLine $boxHelp LightGreen "The muli-functional network troubleshooter!"
    $boxHelp.AppendText("`r`n")
    $boxHelp.SelectionFont = New-Object System.Drawing.Font('Calibri',10)
    Append-ColoredLine $boxHelp Red "Select a tool and begin trouble-shooting! ;)"

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