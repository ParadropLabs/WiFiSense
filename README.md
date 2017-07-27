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
* SCAN_CHANNELS: List of channels to scan for data transmissions (default: null).

REPORTING_URL is mandatory.  The chute will not function unless that
environment variable is set.  Other variables have working defaults.

If SCAN_CHANNELS is set, wifisense will hop between the channels in the list to
scan for data transmissions.  It should be a comma-separated string, e.g.
"1,6,11".

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
  },
  "download": {
    "url": "https://github.com/ParadropLabs/WiFiSense"
  }
}
```

Presence Report
---------------

Below is an example of a presence report that wifisense sends to
the recipient specified by the REPORTING_URL.  The network_id is set
based on the value passed through the NETWORK_ID environment variable.
The network_id and/or node_mac fields give the recipient a method to
distinguish different sensors.  The probe_requests array contains an
entry for each distinct device detected with counts and signal strengths.
Although the field is called "probe_requests", wifisense is not limited
to counting probe requests and detects other 802.11 frame types for a
more complete view of the wireless environment.  Finally, the associated
field is not valid in the current version of wifisense.  It is always
set to false because wifisense does not currently track stations'
association status.

```json
{ network_id: 0,
  node_mac: 'xx:xx:xx:xx:xx:xx',
  version: 1,
  probe_requests:
   [ { mac: 'yy:yy:yy:yy:yy:yy',
       count: 1,
       min_signal: -85,
       max_signal: -85,
       avg_signal: -85,
       last_seen_signal: -85,
       first_seen: 1501171051,
       last_seen: 1501171051,
       associated: false },
     { mac: 'zz:zz:zz:zz:zz:zz',
       count: 40,
       min_signal: -85,
       max_signal: -80,
       avg_signal: -82,
       last_seen_signal: -81,
       first_seen: 1501170885,
       last_seen: 1501171061,
       associated: false },
     ... 921 more items ] }
```
