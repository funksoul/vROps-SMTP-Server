if (-not (Test-Path Env:\VIRTUAL_ENV)) {
    Scripts\Activate.ps1
}
if (-not (Test-Path Env:\SERVERDIR)) {
    New-Item Env:\SERVERDIR -Value $Env:VIRTUAL_ENV
}

#python smtpserver.py
python smtpserver.py --loglevel DEBUG
