# Palo Alto Override and Local Configuration Finder

This script will help you more quickly identify configuration overrides and unwanted local configurations on Palo Alto firewalls that are being managed by a Panorama system. The script will scan the Panorama, identify connected devices, and then compare template and running configurations to find overlaps. It will also highlight any part of the running configuration that is not part of a template and is not covered by the ignore list.

The output is a list of Xpaths and can be either printed to the terminal or placed in a timestamped file.

### Usage

```
Usage: palo_override_finder.py [-h] [-v] [-c] [-r MAX_OPEN] [-k API_KEY] [-i IGNORE_XPATH]
                               [-t TARGET] [-d] [-o FILE_PATH]
                               [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}] panorama
```
```
Example:

  $ python3 palo_override_finder.py 192.0.2.1
```
                               
The basic execution of the script requires an API key for an account with read privileges on the running and template configurations on the firewalls, as well as operational commands on the Panorama. The API key can be provided through arguments or placed in the configuration file.

```
-v, --query-via-panorama
                      Add this option to use Panorama as a proxy when querying the firewalls. Default: False
-c, --ignore-certs    Don't check for valid certificates when connecting. Default: Validate certificates
-r MAX_OPEN, --max-open MAX_OPEN
                      How many firewalls the script will query simultaneously. Default: 10
-k API_KEY, --api-key API_KEY
                      A valid API key with read privileges for the devices. Default: retrieve the key from
                      palo_override_finder.cfg file
-i IGNORE_XPATH, --ignore-xpath IGNORE_XPATH
                      Xpaths to ignore when checking for local firewall configurations. All the nodes identified by
                      the given Xpaths will be ignored. Add multiple Xpaths by passing the -i argument multiple
                      times. This ignore list is applied when checking for local configurations, NOT when checking
                      for overrides. Default: MGMT IP config, Panorama, and HA (see the palo_override_finder.cfg
                      file)
-t TARGET, --target TARGET
                      Limit analysis to the given serials. Example: -t 01230 -t 01231 -t 01232 -t 01233 Default:
                      analyze all firewalls
-d, --print-results   Print details of the overrides to terminal instead of outputting to file. Default: False
-o FILE_PATH, --file-path FILE_PATH
                      The base path in which to create the output files with the overrides. A folder will be created
                      for every serial number, containing the timestamped files for every run. Default: same folder
                      as the script.
-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --debug-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                      Logging message verbosity. Default: WARNING
```

### Local configuration finder

In addition to detecting overrides, the script will also look for any XML elements in the running config that have 1. no descendants, 2. some kind of attribute or text, and 3. are not identified by the ignore list. The default ignore list can be found in the palo_override_finder.cfg file and will cause the script to ignore any local configuration of the MGMT port, Panorama addresses, high availability, as well as some predefined reports and default crypto profiles that are present in any freshly reset firewall.

The ignore list can consist of any Xpath supported by lxml and is intended to reduce noise in the results. It is only applied while searching for local configurations, and will NOT filter out detected overrides.

### Panorama Proxying

With the -v argument, the script can optionally query all firewalls through the Panorama IP. In this mode the only open port required is TCP 443 between the script and the Panorama, instead of TCP 443 between the script and all firewalls involved in the run.

### License

This project is licensed under the [MIT License](LICENSE).
