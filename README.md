Paradrop Wi-Fi Sense
====================

This project is a Paradrop chute that detects nearby Wi-Fi devices and sends
periodic reports to a configurable server endpoint.

Environment Variables
---------------------

* NETWORK_ID: Integer ID for the data source (default: 0).
* REPORTING_INTERVAL: Integer time (in seconds) between reports (default: 30).
* REPORTING_URL: The data will be sent with an HTTP POST to this URL.
* SIGNING_KEY: Secret key used to produce a SHA256 HMAC signature (default: null).

REPORTING_URL is mandatory.  The chute will not function unless that
environment variable is set.  Other variables have working defaults.

Chute Configuration
-------------------

This chute requires a monitor mode interface, so make sure you have that
enabled when launching it on Paradrop.  Below is an example configuration.

```json
{
  "net": {
    "monitor": {
      "type": "wifi",
      "intfName": "mon0",
      "mode": "monitor"
    }
  },
  "environment": {
    "NETWORK_ID": 0,
    "REPORTING_INTERVAL": 30,
    "REPORTING_URL": "http://example.com/wifiReport",
    "SIGNING_KEY": "secret"
  }
  "download": {
    "url": "https://github.com/ParadropLabs/WiFiSense"
  }
}
```
