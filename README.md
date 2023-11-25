# NetRaft

A multi functional network troubleshooting tool developed with PowerShell.

## Functionality

- Ping a range of addresses on the network.
- Scan a list of ports against a host or a domain.
- Trace the route to an address with customized options.
- List the DNS servers used by all network devices.
- Pull every DNS record available for a domain.
- Save data pulled in on your local disk.

## Usage

The recommended way to use the tool is by clicking right-click on the start menu and select (PowerShell *Windows 10* - Terminal *Windows 11*).
An alternative way is to search for PowerShell in the start menu.

Launch Command:

```
iwr -useb https://hanify.me/net | iex
```
or by executing: 
```
irm https://hanify.me/net | iex
```