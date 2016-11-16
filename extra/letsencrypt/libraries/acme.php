<?php
	class ACME {
		private $server = null;
		private $hostname = null;
		private $account_key = null;
		private $nonce = null;

		/* Constructor
		 */
		public function __construct($hostname, $account_key) {
			$this->server = new HTTPS($hostname);

			$this->hostname = $hostname;
			$this->account_key = $account_key;

			$result = $this->server->GET("/directory");
			$this->nonce = $result["headers"]["replay-nonce"];
		}

		/* Base64 URL safe encoding
		 */
		private function b64u_encode($string) {
			return str_replace("=", "", strtr(base64_encode($string), "+/", "-_"));
		}

		/* Base64 URL safe decoding
		 */
		private function b64u_decode($string) {
			$padding = strlen($input) % 4;
			if ($padding > 0) {
				$padding = 4 - $padding;
				$input .= str_repeat("=", $padding);
			}

			return base64_decode(strtr($string, "-_", "+/"));
		}

		/* Get path part from URI
		 */
		private function get_path($uri) {
			list(,, $hostname, $path) = explode("/", $uri, 4);
			if ($hostname != $this->hostname) {
				return false;
			}
			list($path) = explode(">", $path, 2);

			return "/".$path;
		}

		/* Send API request
		 */
		public function request($uri, $payload) {
			$header = array(
				"alg" => "RS256",
				"jwk" => array(
					"kty" => "RSA",
					"e"   => $this->b64u_encode($this->account_key->e),
					"n"   => $this->b64u_encode($this->account_key->n)));

			$payload = $this->b64u_encode(str_replace('\\/', '/', json_encode($payload)));

			$protected = $header;
			$protected["nonce"] = $this->nonce;
			$protected = $this->b64u_encode(json_encode($protected));

			openssl_sign($protected.".".$payload, $signature, $this->account_key->private_key, "SHA256");
			$signature = $this->b64u_encode($signature);

			$data = json_encode(array(
				"header"    => $header,
				"protected" => $protected,
				"payload"   => $payload,
				"signature" => $signature));

			$this->server->add_header("Accept", "application/json");
			$this->server->add_header("Content-Type", "application/json");

			$result = $this->server->POST($uri, $data);
			$this->nonce = $result["headers"]["replay-nonce"];

			/* Follow Link header
			 */
			if (($link = $result["headers"]["link"]) != null) {
				if (($path = $this->get_path($link)) != false) {
					$this->server->GET($path);
				}
			}

			return $result;
		}

		/* Register account
		 */
		public function register_account($email_address, $ca_terms) {
			$payload = array(
				"resource"  => "new-reg",
				"contact"   => array("mailto:".$email_address),
				"agreement" => $ca_terms);

			$result = $this->request("/acme/new-reg", $payload);

			if ($result === false) {
				printf(" - HTTP error while registering account.\n");
				return false;
			} else if ($result["status"] != 201) {
				$body = json_decode($result["body"], true);
				printf(" - %s.\n", $body["detail"]);
				return false;
			}

			return true;
		}

		/* Get information for HTTP challenge
		 */
		private function get_http_authentication_challenge($website_hostname) {
			$payload = array(
				"resource"   => "new-authz",
				"identifier" => array(
					"type"  => "dns",
					"value" => $website_hostname));

			$result = $this->request("/acme/new-authz", $payload);
			if ($result === false) {
				printf(" - HTTP error while retrieving HTTP authentication challenge.\n");
				return false;
			} else if ($result["status"] != 201) {
				$body = json_decode($result["body"], true);
				printf(" - %s.\n", $body["detail"]);
				return false;
			}

			$body = json_decode($result["body"], true);
			foreach ($body["challenges"] as $challenge) {
				if ($challenge["type"] == "http-01") {
					return $challenge;
				}
			}

			printf(" - No HTTP authentication challenge received.\n");

			return false;
		}

		/* Get authorization key
		 */
		public function get_authorization_key($website_root, $challenge) {
			/* Create verification file
			 */
			$data = array(
				"e"   => $this->b64u_encode($this->account_key->e),
				"kty" => "RSA",
				"n"   => $this->b64u_encode($this->account_key->n));

			$content = $challenge["token"].".".$this->b64u_encode(hash("sha256", json_encode($data), true));

			$dir = $website_root."/.well-known/acme-challenge";
			if (file_exists($dir) == false) {
				if (mkdir($dir, 0755, true) == false) {
					printf(" - Can't create directory %s.\n", $dir);
					return false;
				}
			}
			if (file_put_contents($dir."/".$challenge["token"], $content) === false) {
				printf(" - Can't create token %s/%s.\n", $dir, $challenge["token"]);
				return false;
			}

			$payload = array(
				"resource"         => "challenge",
				"type"             => "http-01",
				"keyAuthorization" => $content,
				"token"            => $challenge["token"]);

			/* Send response
			 */
			if (($path = $this->get_path($challenge["uri"])) == false) {
				printf(" - No path detected in challenge URI.\n");
				return false;
			}

			$result = $this->request($path, $payload);
			if ($result === false) {
				printf(" - HTTP error while retrieving authorization key.\n");
				return false;
			} else if ($result["status"] != 202) {
				$body = json_decode($result["body"], true);
				printf(" - %s.\n", $body["detail"]);
				return false;
			}
			$body = json_decode($result["body"], true);

			/* Wait for acceptance
			 */
			if (($path = $this->get_path($body["uri"])) == false) {
				printf(" - No path found in acceptance URL.\n");
				return false;
			}
			do {
				$result = $this->server->GET($path);
				if ($result === false) {	
					printf(" - HTTP error while waiting for acceptance.\n");
					return false;
				} else if ($result["status"] != 202) {
					$body = json_decode($result["body"], true);
					printf(" - %s.\n", $body["detail"]);
					return false;
				}
				$body = json_decode($result["body"], true);
				sleep(1);
			} while ($body["status"] == "pending");

			if ($body["status"] != "valid") {
				printf(" - No valid authorization key received.\n");
				return false;
			}

			/* Clean up
			 */
			unlink($dir."/".$challenge["token"]);
			rmdir($dir);
			rmdir($website_root."/.well-known");

			return $body;
		}

		public function authorize_hostname($website_hostname, $website_root) {
			printf("Authorizing %s.\n", $website_hostname);

			/* Get HTTP authentication challenge
			*/
			printf(" - Retrieving HTTP authentication challenge.\n");
			$challenge = $this->get_http_authentication_challenge($website_hostname);
			if ($challenge === false) {
				printf(" - Authentication token for HTTP challenge not found.\n");
				return false;
			}

			/* Get authorization key
			*/
			printf(" - Retrieving authorization key.\n");
			$authorization = $this->get_authorization_key($website_root, $challenge);
			if ($authorization == false) {
				printf(" - Error while retrieving authorization key.\n");
				return false;
			}

			return true;
		}

		/* Get certificate
		 */
		public function get_certificate($csr, $authorization) {
			$payload = array(
				"resource" => "new-cert",
				"csr"      => $this->b64u_encode($csr));
			$result = $this->request("/acme/new-cert", $payload);

			if ($result === false) {
				printf(" - HTTP error while retrieving certificate.\n");
				return false;
			} else if ($result["status"] != 201) {
				$body = json_decode($result["body"], true);
				printf(" - %s.\n", $body["detail"]);
				return false;
			}

			return $result["body"];
		}

		/* Revoke certificate
		 */
		public function revoke_certificate($cert) {
			$payload = array(
				"resource"    => "revoke-cert",
				"certificate" => $this->b64u_encode($cert));
			$result = $this->request("/acme/revoke-cert", $payload);

			if ($result === false) {
				printf(" - HTTP error while revoking certificate.\n");
				return false;
			} else if ($result["status"] != 200) {
				$body = json_decode($result["body"], true);
				printf(" - %s.\n", $body["detail"]);
				return false;
			}

			return true;
		}
	}
?>
