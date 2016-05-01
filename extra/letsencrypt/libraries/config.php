<?php
	class config {
		private $config = array();

		public function __construct($config_file) {
			if (file_exists($config_file) == false) {
				return array();
			}

			/* Read configuration file
			 */
			$config = array();
			foreach (file($config_file) as $line) {
				$line = trim(preg_replace("/(^|\s)#.*/", "", $line));
				$line = rtrim($line);

				if ($line === "") {
					continue;
				}

				if (($prev = count($config) - 1) == -1) {
					array_push($config, $line);
				} else if (substr($config[$prev], -1) == "\\") {
					$config[$prev] = rtrim(substr($config[$prev], 0, strlen($config[$prev]) - 1)) . "|" . ltrim($line);
				} else {
					array_push($config, $line);
				}
			}

			/* Expand keys in values
			 */
			foreach ($config as $line) {
				list($key, $value) = explode("=", chop($line), 2);
				$key = trim($key);
				$value = trim($value);

				foreach ($this->config as $k => $v) {
					$value = str_replace("{".$k."}", $v, $value);
				}

				$this->config[$key] = $value;
			}
		}

		public function __get($key) {
			switch ($key) {
				case "content": return $this->config;
			}

			return null;
		}
	}
?>
