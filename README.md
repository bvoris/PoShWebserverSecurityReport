# PoShWebserverSecurityReport
PowerShell Webserver Security Report

I am not responsible for how you use this! Use this at your own risk!

WARNING: Early work in progress

Performs the following tests on a webserver
Validates if TCP ports 21, 22, 53, 80, 443, 8080
Gets HTTP Response Headers
Gets Certificate information
Gets robots.txt data
Gets sitemap.xml data
Gets crossdomain.xml data
Gets input fields names, types, ids and maxlength
Validates if vulnerable URLs exist and are accessible to the internet

Generates a report located here:
C:\temp\PoSh-Security-Report-$URL.html
