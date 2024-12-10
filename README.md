# Palo Alto Override and Local Configuration Finder

This script will help you more quickly identify [configuration overrides](https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/manage-firewalls/manage-templates-and-template-stacks/override-a-template-setting) and unwanted local configurations on Palo Alto firewalls that are being managed by a Panorama or Strata Cloud Manager. The script will scan the Panorama or SCM API, identify connected devices, and then compare template and running configurations of all the firewalls to find overlaps, with an optional ignore list. It will also highlight any part of the running configuration that is not part of a template and is not covered by an ignore list. The output is a list of Xpaths and can be either printed to the terminal or placed in a timestamped file.

The script has been tested with PanOS 10.1, 10.2.

### Usage

```
usage: palo_override_finder.py [-h] [-v] [-c] [-r MAX_OPEN] [-k API_KEY] [-b BEARER_TOKEN]
                               [--scm_client_id SCM_CLIENT_ID] [--scm_client_secret SCM_CLIENT_SECRET]
                               [--scm_tsg_id SCM_TSG_ID] [-i IGNORE_XPATH] [-j IGNORE_OVERRIDES_XPATH] [-t TARGET]
                               [-d] [-o FILE_PATH] [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                               panorama_or_scm
```
```
Example:

  $ python3 palo_override_finder.py 192.0.2.1
  $ python3 palo_override_finder.py scm
```
                               
The basic execution of the script requires an API key for an account with read privileges on the running and template configurations on the firewalls, as well as operational commands on the Panorama or "List Devices" on Strata Cloud Manager. The API key and Bearer token/service account credentials can be provided through arguments or placed in the configuration file.

```
positional arguments:
  panorama_or_scm       Panorama IP address or hostname. Enter "scm" to use Strata Cloud Manager instead.

options:
  -h, --help            show this help message and exit
  -v, --query-via-panorama
                        Add this option to use Panorama as a proxy when querying the firewalls. Default: False
  -c, --ignore-certs    Don't check for valid certificates when connecting. Does not affect connections to SCM.
                        Default: Validate certificates
  -r MAX_OPEN, --max-open MAX_OPEN
                        How many firewalls the script will query simultaneously. Default: 10
  -k API_KEY, --api-key API_KEY
                        A valid firewall or Panorama API key with read privileges for the devices. Default: retrieve
                        the key from palo_override_finder.cfg file
  -b BEARER_TOKEN, --bearer_token BEARER_TOKEN
                        A Strata Cloud Manager API Bearer Token with read privileges to List Devices. This token is
                        only valid for 15 minutes. Generate it from client_id and client_secret following
                        https://pan.dev/scm/docs/getstarted/. Default: retrieve the token from BEARER_TOKEN in
                        palo_override_finder.cfg file
  --scm_client_id SCM_CLIENT_ID
                        A Strata Cloud Manager Service Account client_id with read privileges to List Devices.
                        Default: retrieve the key from palo_override_finder.cfg file, unless a BEARER_TOKEN is passed
                        instead.
  --scm_client_secret SCM_CLIENT_SECRET
                        A Strata Cloud Manager Service Account client_secret with read privileges to List Devices.
                        Default: retrieve the key from palo_override_finder.cfg file, unless a BEARER_TOKEN is passed
                        instead.
  --scm_tsg_id SCM_TSG_ID
                        The TSG ID in which the Strata Cloud Manager managing the devices is located. This, along with
                        scm_client_id and scm_client_secret, is required to generate the BEARER_TOKEN unless this
                        token is passed to the script directly. The Bearer token, however, only lasts 15 minutes. with
                        read privileges to List Devices. Default: retrieve the key from palo_override_finder.cfg file
  -i IGNORE_XPATH, --ignore-xpath IGNORE_XPATH
                        Xpaths to ignore when checking for local firewall configurations. All the nodes identified by
                        the given Xpaths will be ignored. Add multiple Xpaths by passing the -i argument multiple
                        times. This ignore list is applied when checking for local configurations, NOT when checking
                        for overrides. Default: MGMT IP config, Panorama, and HA (see the palo_override_finder.cfg
                        file)
  -j IGNORE_OVERRIDES_XPATH, --ignore-overrides-xpath IGNORE_OVERRIDES_XPATH
                        Xpaths to ignore when checking for overrides. All the nodes identified by the given Xpaths
                        will be ignored. Add multiple Xpaths by passing the -j argument multiple times. Default: None
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

In addition to detecting overrides, the script will also look for any XML elements in the running config that have 1. no descendants, 2. some kind of attribute or text, and 3. are not identified by the ignore list. The default ignore list can be found in the [palo_override_finder.cfg](palo_override_finder.cfg) file and will cause the script to ignore any local configuration of the MGMT port, Panorama addresses, high availability, as well as some predefined reports and default crypto profiles that are present in any freshly reset firewall.

The ignore list can consist of any Xpath supported by lxml and is intended to reduce noise in the results.

### Panorama Proxying

With the -v argument, the script can optionally query all firewalls through the Panorama IP. In this mode the only open port required is TCP 443 between the script and the Panorama, instead of TCP 443 between the script and all firewalls involved in the run.

### Strata Cloud Manager

By passing "scm" instead of the Panorama hostname, the script will take a SCM API Bearer token (or alternatively, client_id client_secret and TSG ID, needed to generate the token) and retrieve the list of firewalls from SCM instead. The rest of the script works as before, querying the firewalls directly at their private IP address.

Reference:

https://pan.dev/scm/docs/access-tokens/

https://pan.dev/scm/api/config/ngfw/setup/list-devices/

### Requirements

- [requests](https://pypi.org/project/requests/) (install with ```pip3 install requests```)
- [lxml](https://pypi.org/project/lxml/) (install with ```pip3 install lxml```)

### License

This project is licensed under the [MIT License](LICENSE).
