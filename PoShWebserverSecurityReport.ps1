#PowerShell Webserver Security Report
#Written by Brad Voris
#Version 1.0
# Change the domain name to the name of the domain you are testing

#Get URL
$URL = "www.DOMAINNAMEHERE.com"
$URL

#Get Server Response and Headers
$Response = invoke-webrequest $URL
$RH = $Response.Headers
$RHHTML = $RH.GetEnumerator() | Select Key, Value | ConvertTo-Html

#Validate Ports 80 & 443 are up
$Port21 = Test-NetConnection $URL -Port "21" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded  | ConvertTo-Html
$Port22 = Test-NetConnection $URL -Port "22" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded  | ConvertTo-Html
$Port53 = Test-NetConnection $URL -Port "53" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded  | ConvertTo-Html
$Port80 = Test-NetConnection $URL -Port "80" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded  | ConvertTo-Html
$Port443 = Test-NetConnection $URL -Port "443" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded | ConvertTo-Html
$Port8080 = Test-NetConnection $URL -Port "8080" | Select ComputerName, RemoteAddress, RemotePort, TCPTestSucceeded  | ConvertTo-Html

#Get Server Certificate Information
#$webcall = Invoke-WebRequest $URL
$servicePoint = [System.Net.ServicePointManager]::FindServicePoint("https://$URL")
$spcgn = $servicePoint.Certificate.GetName()
$spcgin = $servicePoint.Certificate.GetIssuerName()
$spcgf = $servicePoint.Certificate.GetFormat()
$spcgka = $servicePoint.Certificate.GetKeyAlgorithm()
$spcghc = $servicePoint.Certificate.GetHashCode()
$spcgchs = $servicePoint.Certificate.GetCertHashString()
$spcgeds = $servicePoint.Certificate.GetEffectiveDateString()
$spcgeds = $servicePoint.Certificate.GetExpirationDateString()

#Web Spider data
$spiderdata = Invoke-RestMethod  "$URL/robots.txt"

#Sitemap
$sitemap = Invoke-Webrequest "$URL/sitemap.xml" -UseBasicParsing

#Cross-Domain Policy
$crossdomain = Invoke-Webrequest "$URL/crossdomain.xml" -UseBasicParsing

#Get Generator
$generator = $response.AllElements | where {$_.name -eq 'generator'} | select name, content

#Get Input Fields
$ParseInputfields = $response.inputfields
$inputfields = $ParseInputfields.GetEnumerator()| select name, type, id, maxlength | ConvertTo-Html

#Vulnerabilt URL Validation
function Validate-Url
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Uri] $Urls,
        [Parameter()]
        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method = 'Get',
        [Parameter()]
        [switch] $UseDefaultCredentials
    )

    process
    {
        [bool] $succeeded = $false
        [string] $statusCode = $null
        [string] $statusDescription = $null
        [string] $message = $null
        [int] $bytesReceived = 0
        [Timespan] $timeTaken = [Timespan]::Zero 

        $timeTaken = Measure-Command `
            {
                try
                {
                    [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $response = Invoke-WebRequest -UseDefaultCredentials:$UseDefaultCredentials -Method $Method -Uri $Urls
                    $succeeded = $true
                    $statusCode = $response.StatusCode.ToString('D')
                    $statusDescription = $response.StatusDescription
                    $bytesReceived = $response.RawContent.Length

                    Write-Verbose "$($Urls.ToString()): $($statusCode) $($statusDescription) $($message)"
                }
                catch [System.Net.WebException]
                {
                    $message = $Error[0].Exception.Message
                    [System.Net.HttpWebResponse] $exceptionResponse = $Error[0].Exception.GetBaseException().Response

                    if ($exceptionResponse -ne $null)
                    {
                        $statusCode = $exceptionResponse.StatusCode.ToString('D')
                        $statusDescription = $exceptionResponse.StatusDescription
                        $bytesReceived = $exceptionResponse.ContentLength

                        if ($statusCode -in '401', '403', '404')
                        {
                            $succeeded = $true
                        }
                    }
                    else
                    {
                        Write-Warning "$($Urls.ToString()): $($message)"
                    }
                }
            }

        return [PSCustomObject] @{ Url = $Urls; Succeeded = $succeeded; BytesReceived = $bytesReceived; TimeTaken = $timeTaken.TotalMilliseconds; StatusCode = $statusCode; StatusDescription = $statusDescription; Message = $message; }
    }
}
$validatedurls = "$URL/wordpress/readme.html", "$URL/wordpress/readme.html", "$url/xmlrpc.php", "$url/wordpress/xmlrpc.php", "$url/global.asa" , "$url/admin/createUser.php?member=myAdmin", "$url/admin/changePw.php?member=myAdmin&passwd=foo123&confirm=foo123", "$url/admin/groupEdit.php?group=Admins&member=myAdmin&action=add", "$url/admin/createUser.php?member=myAdmin" | Validate-Url | ConvertTo-Html



#HTML Report Building
$Dated = (Get-Date -format F)

$HTMLHead = @"
<!DOCTYPE html>
<HEAD>
<META charset="UTF-8">
<TITLE>PowerShell Webserver Security Report for $URL</TITLE>
<CENTER>
<STYLE>$CSS</STYLE></HEAD>
"@

#HTML Body Coding
$HTMLBody = @"
<TABLE BORDER=1>
<TR>
<TD>
<CENTER><B>PowerShell Webserver Security Report for $URL</B><CENTER/>
<CENTER>Executed: $Dated<CENTER />
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Webserver Ports</B><CENTER />
<TABLE BORDER=1><TR><TD><B>Port 21</B></TD><TD><B>Port 22</B></TD></TR><TR><TD>$Port21</TD><TD>$Port22</TD></TR></TABLE>
<TABLE BORDER=1><TR><TD><B>Port 53</B></TD><TD><B>Port 80</B></TD></TR><TR><TD>$Port53</TD><TD>$Port80</TD></TR></TABLE>
<TABLE BORDER=1><TR><TD><B>Port 443</B></TD><TD><B>Port 8080</B></TD></TR><TR><TD>$Port443</TD><TD>$Port8080</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>HTTP Response Headers</B><CENTER />
<TABLE BORDER=1><TR><TD>$RHHTML</TD></TR></TABLE>
<CENTER><B>Webserver Certificate Information</B><CENTER />
<TABLE BORDER=1>
<TR><TD>Host Name</TD><TD>$spcgn</TD></TR>
<TR><TD>Issuer Name</TD><TD>$spcgin</TD></TR>
<TR><TD>Cert Format</TD><TD>$spcgf</TD></TR>
<TR><TD>Key Algorithm</TD><TD>$spcgka</TD></TR>
<TR><TD>Hash Code</TD><TD>$spcghc</TD></TR>
<TR><TD>Hash String</TD><TD>$spcgchs</TD></TR>
<TR><TD>Effective Date</TD><TD>$spcgeds</TD></TR>
<TR><TD>Expiration Date</TD><TD>$spcgeds</TD></TR>
</TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Robot.txt Spiderdata</B><CENTER />
<TABLE BORDER=1><TR><TD>$spiderdata</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Get Generator Data Element</B><CENTER />
<TABLE BORDER=1><TR><TD>$generator</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Get Input Fields</B><CENTER />
<TABLE BORDER=1><TR><TD>$inputfields</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>SiteMap</B><CENTER />
<TABLE BORDER=1><TR><TD>$sitemap</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Cross Domain Policy</B><CENTER />
<TABLE BORDER=1><TR><TD>$crossdomain</TD></TR></TABLE>
</TD>
</TR>
<TR>
<TD>
<CENTER><B>Vulnerable URLs</B><CENTER />
<TABLE BORDER=1><TR><TD>$validatedurls</TD></TR></TABLE>
</TD>
</TR>
</TABLE>
"@


# Export to HTML
$Script | ConvertTo-HTML -Head $HTMLHead -Body $HTMLBody | Out-file "C:\temp\PoSh-Security-Report-$URL.html"

#Clear Screen
CLS
