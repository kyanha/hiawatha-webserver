Open letsencrypt.conf, change the account email address and key size according
to your needs.

Before you can request a certificate, you need to register an account at the
Let's Encrypt CA. You can do this via the command: ./letsencrypt register

When running the tool for the first time, it will create a Let's Encrypt
account key. Make sure you make a backup of this account.key file.

You can request a website certificate via: ./letsencrypt request <hostname>
A virtual host for <hostname> must be present in the webserver configuration
and you must have write access rights to its website root. The <hostname>
must be the first hostname for that virtual host. All other hostnames will
be used as alternative hostnames for the certificate. Wildcards are not (yet)
supported by Let's Encrypt, so they will not be used as alternative names
in the certificate. Unless you specify a filename as the third parameter,
the requested certificate will be stored in the file <hostname>.pem. When
requesting a Let's Encrypt certificate, make sure your website is reachable
via HTTP (port 80). This is necessary because the Let's Encrypt CA will
request a file from it, which the script will create in the webroot in order
to prove you are the owner of that website.

After properly testing, open letsencrypt.conf, comment the testing CA hostname
(the LE_CA_HOSTNAME setting), uncomment the production CA hostname, register
your account key at the production server and request the final version of your
website certificate.

Certificates will be written to a file in the directory of this script. If you
run the script as user root, the certificate will be written to the directory
configured via the WEBSERVER_CERT_DIR setting.

To automatically renew certificates that are about to get expired, run the
letsencrypt tool with the parameter 'renew' as a cronjob of the user root.
Add the parameter 'restart' to automatically restart the webserver when one or
more certificates have been renewed.
