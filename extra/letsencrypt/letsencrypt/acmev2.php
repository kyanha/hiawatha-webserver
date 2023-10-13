<?php
	/* Copyright (c) by Hugo Leisink <hugo@leisink.net>
	 *
	 * This program is free software; you can redistribute it and/or modify
	 * it under the terms of the GNU General Public License as published by
	 * the Free Software Foundation; version 2 of the License. For a copy,
	 * see http://www.gnu.org/licenses/gpl-2.0.html.
	 *
	 * This program is distributed in the hope that it will be useful,
	 * but WITHOUT ANY WARRANTY; without even the implied warranty of
	 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	 * GNU General Public License for more details.
	 */

	class ACMEv2 {
		private $server = null;
		private $hostname = null;
		private $account_key_file = null;
		private $account_key = null;
		private $account_id = 0;
		private $nonce = null;
		private $logfile = null;
		private $first_post = true;
		private $last_result = null;

		/* Constructor
		 */
		public function __construct($hostname, $account_key_file) {
			$this->server = new HTTPS($hostname);
			$this->hostname = $hostname;
			$this->account_key_file = $account_key_file;
			$this->account_key = new RSA($account_key_file);

			$this->logfile = new logfile("debug_letsencrypt");

			/* Read account key
			 */
			if (($fp = fopen($this->account_key_file, "r")) == false) {
				return;
			}

			$line = fgets($fp);
			fclose($fp);

			list($key, $value) = explode(":", rtrim($line));

			if ($key == "ID") {
				$this->account_id = $value;
			}
		}

		/* Magic GET method
		 */
		public function __get($key) {
			switch ($key) {
				case "account_id": return $this->account_id;
			}

			return null;
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
			$parts = explode("/", $uri, 4);

			if (count($parts) < 4) {
				printf(" - URI %s is invalid.\n", $uri);
				return false;
			}

			list(,, $hostname, $path) = $parts;
			if ($hostname != $this->hostname) {
				printf(" - Hostname %s in URL does not match.\n", $hostname);
				return false;
			}

			return "/".$path;
		}

		/* Send API GET request
		 */
		public function GET($uri, $expected_status = 200) {
			$this->logfile->add_entry("GET %s", $uri);

			if (($result = $this->server->GET($uri)) === false) {
				return false;
			}

			$this->last_result = $result;

			$this->logfile->add_variable($result, "Server response");

			if ($result["status"] != $expected_status) {
				return false;
			}

			return $result;
		}

		/* Send API POST request
		 */
		public function POST($uri, $payload, $expected_status = 200) {
			if ($this->first_post) {
				/* Get first nonce
				 */
				if (($result = $this->GET("/acme/new-nonce", 204)) === false) {
					printf(" - Error connecting to Let's Encrypt CA server.\n");
					return false;
				}
				$this->nonce = $result["headers"]["replay-nonce"];

				$this->first_post = false;
			}

			$this->logfile->add_entry("POST %s", $uri);
			$this->logfile->add_variable($payload, "Payload");

			$protected = array("alg" => "RS256");

			if (in_array($uri, array("/acme/new-acct"))) {
				$protected["jwk"] = array(
					"kty" => "RSA",
					"e"   => $this->b64u_encode($this->account_key->e),
					"n"   => $this->b64u_encode($this->account_key->n));
			} else {
				if ($this->account_id == 0) {
					printf(" - Account not registered yet.\n");
					$this->logfile->clean();
					return false;
				}

				$protected["kid"] = sprintf("https://%s/acme/acct/%s", $this->hostname, $this->account_id);
			}
			$protected["nonce"] = $this->nonce;
			$protected["url"] = "https://".$this->hostname.$uri;
			$protected = $this->b64u_encode(json_encode($protected));
			$payload = $this->b64u_encode(str_replace('\\/', '/', json_encode($payload)));

			openssl_sign($protected.".".$payload, $signature, $this->account_key->private_key, "SHA256");
			$signature = $this->b64u_encode($signature);

			$data = json_encode(array(
				"protected" => $protected,
				"payload"   => $payload,
				"signature" => $signature));

			$this->server->add_header("Content-Type", "application/jose+json");

			if (($result = $this->server->POST($uri, $data)) === false) {
				printf(" - HTTP error for %s.\n", $uri);
				return false;
			}

			$this->last_result = $result;

			$this->logfile->add_variable($result, "Server response");

			if ($result["status"] != $expected_status) {
				if (($body = json_decode($result["body"], true)) !== null) {
					if (isset($body["detail"])) {
						printf(" - %s\n", $body["detail"]);
					}
				}
				return false;
			}

			$this->nonce = $result["headers"]["replay-nonce"];

			return $result;
		}

		/* Register account
		 */
		public function register_account($email_address) {
			$this->logfile->add_entry(">>> Registering account.");

			$payload = array(
				"contact"              => array("mailto:".$email_address),
				"termsOfServiceAgreed" => true);

			if (($result = $this->POST("/acme/new-acct", $payload, 201)) == false) {
				return false;
			}

			$parts = explode("/", $this->last_result["headers"]["location"]);
			$account_id = (int)array_pop($parts); 

			$this->logfile->clean();

			return $account_id;
		}

		/* Order certificate
		 */
		public function order_certificate($website_hostnames) {
			$this->logfile->add_entry(">>> Ordering certificate for %s.", $website_hostnames[0]);

			$identifiers = array();
			foreach ($website_hostnames as $hostname) {
				array_push($identifiers, array(
					"type"  => "dns",
					"value" => $hostname));
			}

			$payload = array("identifiers" => $identifiers);

			/* Request certificate
			 */
			if (($result = $this->POST("/acme/new-order", $payload, 201)) == false) {
				return false;
			}

			if (($body = json_decode($result["body"], true)) === null) {
				return false;
			}

			if ($body["status"] == "processing") {
				printf(" - The server is still processing the previous request.\n");
				printf(" - %s\n", str_replace("/finalize-order", "", $body["finalize"]));
				return false;
			}

			foreach ($body["identifiers"] as $i => $identifier) {
				$body["identifiers"][$i]["path"] = $this->get_path($body["authorizations"][$i]);
			}

			return array(
				"identifiers" => $body["identifiers"],
				"finalize"    => $body["finalize"]);
		}

		/* Get challenge
		 */
		public function get_challenge($order) {
			if (($result = $this->GET($order["path"])) === false) {
				return false;
			}

			if (($body = json_decode($result["body"], true)) === null) {
				return false;
			}

			foreach ($body["challenges"] as $challenge) {
				if ($challenge["type"] != "http-01") {
					continue;
				}

				$data = array(
					"e"   => $this->b64u_encode($this->account_key->e),
					"kty" => "RSA",
					"n"   => $this->b64u_encode($this->account_key->n));
				$key = $challenge["token"].".".$this->b64u_encode(hash("sha256", json_encode($data), true));

				return array(
					"path"  => $this->get_path($challenge["url"]),
					"key"   => $key,
					"token" => $challenge["token"]);
			}

			printf(" - No HTTP challenge was offered.\n");
			return false;
		}

		/* Authorize host
		 */
		public function authorize_host($challenge) {
			$payload = array("keyAuthorization" => $challenge["key"]);
			if (($result = $this->POST($challenge["path"], $payload)) == false) {
				return false;
			}

			return true;
		}

		/* Poll authorization is valid
		 */
		public function authorization_valid($order) {
			if (($result = $this->GET($order["path"])) === false) {
				return false;
			}

			if (($body = json_decode($result["body"], true)) === null) {
				return false;
			}

			foreach ($body["challenges"] as $challenge) {
				if ($challenge["type"] != "http-01") {
					continue;
				}

				if ($challenge["status"] == "valid") {
					return true;
				}
			}

			return false;
		}

		/* Finalize
		 */
		public function finalize_order($order, $csr) {
			if (($path = $this->get_path($order["finalize"])) === false) {
				return false;
			}

			$payload = array("csr" => $this->b64u_encode($csr));
			if (($result = $this->POST($path, $payload)) == false) {
				return false;
			}
			if (($body = json_decode($result["body"], true)) === null) {
				return false;
			}

			return array(
				"status"   => $body["status"],
				"location" => $this->get_path($result["headers"]["location"]),
				"path"     => $this->get_path($body["certificate"]));
		}

		/* Poll certificate is ready
		 */
		public function certificate_ready($path) {
			if (($result = $this->GET($path)) === false) {
				return false;
			}

			if (($body = json_decode($result["body"], true)) === null) {
				return false;
			}

			if ($body["status"] != "valid") {
				return false;
			}

			return true;
		}

		/* Get certificate
		 */
		public function get_certificate($certificate) {
			if (($result = $this->GET($certificate["path"])) == false) {
				return false;
			}

			$this->logfile->clean();

			return $result["body"];
		}

		/* Revoke certificate
		 */
		public function revoke_certificate($cert) {
			$this->logfile->add_entry(">>> Revoking certificate.");

			$payload = array("certificate" => $this->b64u_encode($cert));
			if (($result = $this->POST("/acme/revoke-cert", $payload)) == false) {
				return false;
			}

			$this->logfile->clean();

			return true;
		}
	}
?>
