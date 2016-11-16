<?php
	class LetsEncrypt {
		private $acme = null;
		private $hiawatha = null;

		/* Constructor
		 */
		public function __construct($account_key) {
			$this->acme = new ACME(LE_CA_HOSTNAME, $account_key);
			$this->hiawatha = new Hiawatha_config(HIAWATHA_CONFIG_DIR);
		}

		/* Extract CA url from certificate
		 */
		private function get_CA_url($certificate) {
			if (($x509 = openssl_x509_parse($certificate)) == false) {
				return false;
			}

			$ca_info = $x509["extensions"]["authorityInfoAccess"];

			$ca_info = explode("\n", $ca_info);
			foreach ($ca_info as $item) {
				list($label, $info) = explode(" - ", $item);
				if ($label != "CA Issuers") {
					continue;
				}

				list($type, $url) = explode(":", $info, 2);
				if ($type != "URI") {
					return false;
				}

				return $url;
			}

			return false;
		}

		/* Remove hostnames containing a wildcard from list
		 */
		private function remove_wildcard_hostnames($hostnames, $main) {
			$result = array();

			foreach ($hostnames as $hostname) {
				if (substr($hostname, 0, 2) != "*.") {
					array_push($result, $hostname);
				} else {
					$domain = substr($hostname, 2);
					array_push($result, "www.".$domain);
					array_push($result, $domain);
				}
			}

			return array_diff(array_unique($result), array($main));
		}

		/* Check if certificate is in PEM format
		 */
		private function is_pem_format($cert) {
			return substr($cert, 0, 10) == "-----BEGIN";
		}

		/* Convert certificate in DER format to PEM format
		 */
		private function convert_to_pem($der_cert) {
			$pem_data = chunk_split(base64_encode($der_cert), 64, "\n");
			return "-----BEGIN CERTIFICATE-----\n".$pem_data."-----END CERTIFICATE-----\n";
		}

		/* Register account
		 */
		public function register_account($email_address, $ca_terms) {
			if ($this->acme->register_account($email_address, $ca_terms)) {
				printf("Account registered successfully.\n");
			}
		}

		/* Request Let's Encrypt certificate
		 */
		public function request_certificate($website_hostname, $cert_file = null) {
			/* Website root
			 */
			if (($website_root = $this->hiawatha->get_website_root($website_hostname)) == null) {
				printf("Hostname %s not found in Hiawatha configuration.\n", $website_hostname);
				return false;
			}

			/* Authorize hostname
			 */
			if ($this->acme->authorize_hostname($website_hostname, $website_root) == false) {
				return false;
			}

			/* Alternative hostnames
			 */
			$website_alt_hostnames = $this->hiawatha->get_website_hostnames($website_hostname);
			$website_alt_hostnames = $this->remove_wildcard_hostnames($website_alt_hostnames, $website_hostname);
			foreach ($website_alt_hostnames as $alt_hostname) {
				if ($this->acme->authorize_hostname($alt_hostname, $website_root) == false) {
					return false;
				}
			}

			/* Generate RSA key
			 */
			printf("Generating RSA key.\n");
			$rsa = new RSA(CERTIFICATE_RSA_KEY_SIZE);

			/* Generate CSR
			 */
			if (($openssl_config = file_get_contents("libraries/openssl.conf")) == false) {
				printf(" - Error reading OpenSSL configuration template.\n");
				return false;
			}

			array_unshift($website_alt_hostnames, $website_hostname);
			$san = implode(", ", array_map(function ($dns) { return "DNS:" . $dns; }, $website_alt_hostnames));
			$openssl_config = str_replace("{SUBJECT_NAME}", $san, $openssl_config);
			$openssl_config = str_replace("{RSA_KEY_SIZE}", CERTIFICATE_RSA_KEY_SIZE, $openssl_config);

			$openssl_config_file = "/tmp/".$challenge["token"].".conf";
			if (file_put_contents($openssl_config_file, $openssl_config) == false) {
				printf("Error writing temporary OpenSSL configuration.\n");
				return false;
			}

			printf("Generating CSR.\n");
			$dn = array(
				"commonName"             => $website_hostname,
				"emailAddress"           => ACCOUNT_EMAIL_ADDRESS);
			$csr_config = array(
				"digest_alg"             => "sha256",
				"config"                 => $openssl_config_file);
			$csr = openssl_csr_new($dn, $rsa->private_key, $csr_config);
			openssl_csr_export($csr, $csr);

			unlink($openssl_config_file);

			preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);
			$csr = base64_decode($matches[1]);

			/* Get certificate
			 */
			print("Retrieving certificate.\n");
			$certificate = $this->acme->get_certificate($csr, $authorization);
			if ($certificate == false) {
				printf(" - Error while retrieving certificate.\n");
				return false;
			}

			if ($this->is_pem_format($certificate) == false) {
				$certificate = $this->convert_to_pem($certificate);
			}

			/* Output certificate
			 */
			if ($cert_file == null) {
				$dir = (posix_getuid() == 0) ? HIAWATHA_CERT_DIR."/" : "";
				$cert_file = $dir.$website_hostname.".pem";
				$number = 1;
				while (file_exists($cert_file)) {
					$cert_file = $dir.$website_hostname."-".$number.".pem";
					$number++;
				}
				printf("Using %s as output file.\n", $cert_file);
			}

			if (($fp = fopen($cert_file, "w")) == false) {
				printf("\n%s\n%s\n", $rsa->private_key, $certificate);
			} else {
				printf("Writing private key and certificate to file.\n");
				fputs($fp, $rsa->private_key."\n");
				fputs($fp, $certificate."\n");
				fclose($fp);
				chmod($cert_file, 0600);
			}

			/* Attach CA certificate
			 */
			if (($ca_url = $this->get_CA_url($certificate)) != false) {
				printf("Retrieving CA certificate.\n");
				list(,, $ca_hostname, $ca_path) = explode("/", $ca_url, 4);
				$ca = new HTTP($ca_hostname);
				$result = $ca->GET("/".$ca_path);
				if ($result["status"] == 200) {
					$ca_cert = $result["body"];
					if ($this->is_pem_format($ca_cert) == false) {
						$ca_cert = $this->convert_to_pem($ca_cert);
					}

					if (($fp = fopen($cert_file, "a")) == false) {
						printf("%s\n", $ca_cert);
					} else {
						printf("Writing CA certificate to file.\n");
						fputs($fp, $ca_cert."\n");
						fclose($fp);
						chmod($cert_file, 0400);
					}
				}
			}

			printf("\n");

			return true;
		}

		/* Revoke Let's Encrypt certificate
		 */
		public function revoke_certificate($cert_file) {
			if (($cert = file_get_contents($cert_file)) == false) {
				printf(" - Certificate file %s not found.\n", $cert_file);
				return;
			}

			preg_match('~BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE~s', $cert, $matches);
			if (($cert = $matches[1]) == null) {
				printf(" - Invalid certificate file.\n");
			}
			$cert = base64_decode($cert, true);

			if ($this->acme->revoke_certificate($cert)) {
				printf("Certificate revoked successfully.\n");
			}
		}
	}
?>
