<div align="center"><img src="icon/icon_v2_universal.png" alt ="Hacker-Scoper icon"></div>
<br>
<p align="center">
  <a href="https://github.com/ItsIgnacioPortal/hacker-scoper/actions/workflows/gorelease.yml"><img src="https://github.com/ItsIgnacioPortal/Hacker-Scoper/actions/workflows/gorelease.yml/badge.svg?event=push"></a>
  <a href="https://go.dev"><img alt="Golang icon" src="https://img.shields.io/badge/Built_with-GoLang-00acd7?logo=go"></a>
  <a href="https://github.com/ItsIgnacioPortal/Hacker-Scoper/releases"><img alt="Link to the latest version" src="https://img.shields.io/github/v/release/itsignacioportal/hacker-scoper"></a>
  <a href="https://www.bestpractices.dev/projects/10594"><img alt="OpenSSF best practices badge." src="https://www.bestpractices.dev/projects/10594/badge?c"></a>
  <a href="https://github.com/vavkamil/awesome-bugbounty-tools"><img alt="Mentioned in Awesome Bug Bounty Tools." src="https://awesome.re/mentioned-badge.svg"></a>
</p>


---

Hacker-Scoper is a CLI tool programmed in GoLang designed to assist cybersecurity professionals in bug bounty programs. Given a mixed list of targets (URLs/IPs), it can quickly filter them to match the bug-bounty program's scope. The scope can be supplied manually, or it can also be detected automatically by just giving hacker-scoper the name of the targeted company.

This project is developed and maintained by [ItsIgnacioPortal](https://github.com/ItsIgnacioPortal).

## 🌟 Features

- **Automatic scope detection**: Hacker-Scoper maintains an automatically-updated cached database of public program scopes. This means you don't need to manually specify the program scope unless the bug bounty program is private. You just need to supply the company name (`-c company-name-here`).

- **Easy customization**: You can load the scope of any private program into files named `.inscope` for inscope assets, and `.noscope` for out-of-scope assets.

- **Match any asset**: Hacker-Scoper works with IPv4, IPv6, and any URL format (including URLs with non-conventional schemes, like `sql://` or `redis://`).

- **Wildcard support**: Hacker-Scoper supports wildcards in any part of your domain-name scopes, allowing you to use filters like `amzn*.example.com` and `dev.*.example.com`.

- **Regex support**: You can use Regular Expressions (regex) as scopes to filter any assets. All regex scopes _must_ start with `^` and end with `$`. For example: `^\w+:\/\/db[0-9][0-9][0-9]\.mycompany\.ec2\.amazonaws\.com.*$`

- **CIDR Range support**: You can use CIDR ranges in your scopes to filter IP addresses, for example: `10.49.20.0/24` for IPv4 and `2001:DB8::/32` for IPv6.

- **Nmap octet ranges support**: Just like nmap, you may specify IPv4 scopes using octet ranges, like for example: `192.168.1-3.1`. That example would match the IPs `192.168.1.1`, `192.168.2.1` and `192.168.3.1`. You can also specify a comma-separated list of numbers for each octet, for example: `192.168.1-3,5.1`, which would match the IPs: `192.168.1.1`, `192.168.2.1`, `192.168.3.1` and `192.168.5.1`.

- **Automation friendly**: Use the `-ch`/`--chain-mode` argument to disable the fancy text decorations and output only the in-scope assets. Hacker-scoper also supports input from stdin.

- **Compatible**: Hacker-Scoper is compatible with Windows, Linux and MacOS in all architectures.

- **Blazing-fast**: Hacker-Scoper is extremely fast at processing targets, as it leverages several optimization techniques as well as built-in multithreading.

- **Flexible**: For any companies with vaguely defined scopes, you can enable or disable scope wildcard/CIDR parsing using the command-line argument `-ie`/`--inscope-explicit-level`.

- **Misconfiguration detection**: Using TLD-Based detection, hacker-scoper can automatically detect misconfigurations in bug-bounty program scopes. For example: Sometimes bug bounty programs set APK package names such as `com.my.businness.gatewayportal` as `web_application` resources instead of as `android_application` resources in their program scope, causing trouble for anyone using automatic tools. Hacker-Scoper automatically detects these errors and notifies the user.

## 📦 Installation

**Using Chocolatey**

```
choco install hacker-scoper
```

**Using go install**

```
go install github.com/ItsIgnacioPortal/hacker-scoper/src/hacker-scoper
```

**From the releases page**

Download a pre-built binary from [the releases page](https://github.com/ItsIgnacioPortal/hacker-scoper/releases)

<br>

## 🎥 Demos

### Demo with company lookup
[![asciicast](https://asciinema.org/a/llZUBG5BC754rA2yy0Gx7EBqg.svg)](https://asciinema.org/a/llZUBG5BC754rA2yy0Gx7EBqg)
<br>
<br>
<br>
<br>

### Demo with custom scopes file
[![asciicast](https://asciinema.org/a/f1IU5U2wv37D3YDclA1EBcQ6U.svg)](https://asciinema.org/a/f1IU5U2wv37D3YDclA1EBcQ6U)

## 🏭 Company scope matching
- **Q: How does the "company" scope matching actually work?**
- A: It works by looking for company-name matches in a cached copy of the [firebounty](https://firebounty.com/) database. The company name that you specify will be lowercase'd, and then the tool will check if any company name in the database contains that string. Once it finds a name match, it will filter your supplied targets according to the scopes that firebounty detected for that company. You can test how this would perform by just searching some name in [the firebounty website](https://firebounty.com/).

## 🤔 Usage
Usage: hacker-scoper --file /path/to/targets [--company company | --inscopes-file /path/to/inscopes [--outofscopes-file /path/to/outofscopes] [--enable-private-tlds]] [--inscope-explicit-level INT] [--noscope-explicit-level INT] [--chain-mode] [--database /path/to/firebounty.json] [--include-unsure] [--output /path/to/outputfile] [--hostnames-only]

### Usage examples:
- Example: Cat a file, and lookup scopes on firebounty
  `cat recon-targets.txt | hacker-scoper -c google`

- Example: Cat a file, and use the .inscope & .noscope files
  `cat recon-targets.txt | hacker-scoper`

- Example: Manually pick a file, lookup scopes on firebounty, and set inscope explicit-level
  `hacker-scoper -f recon-targets.txt -c google -ie 2`

- Example: Manually pick a file, use custom scopes and out-of-scope files, and set inscope explicit-level
  `hacker-scoper -f recon-targets.txt -ins inscope -oos noscope.txt -ie 2`

**Usage notes:** If no company and no inscope file are specified, hacker-scoper will look for ".inscope" and ".noscope" files in the current or in parent directories.

### Table of all possible arguments:
| Short | Long | Description |
|-------|------|-------------|
| -c | --company |  Specify the company name to lookup. |
| -f | --file |  Path to your file containing URLs/domains/IPs |
| -ins | --inscope-file |  Path to a custom plaintext file containing scopes |
| -oos | --outofscope-file |  Path to a custom plaintext file containing scopes exclusions |
| -ie<br>-oe | --inscope-explicit-level int<br>--noscope-explicit-level  int|  How explicit we expect the scopes to be:    <br> 1 (default): Include subdomains in the scope even if there's not a wildcard in the scope.    <br> 2: Include subdomains in the scope only if there's a wildcard in the scope.    <br> 3: Include subdomains/IPs in the scope only if they are explicitly within the scope. CIDR ranges and wildcards are disabled. |
|  | --enable-private-tlds | Set this flag to enable the use of company scope domains with private TLDs. This essentially disables the bug-bounty-program misconfiguration detection. |
| -ch | --chain-mode |  In "chain-mode" we only output the important information. No decorations. Default: false |
|  | --database | Custom path to the cached firebounty database |
| -iu | --include-unsure |  Include "unsure" assets in the output. An unsure asset is an asset that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program. |
| -o | --output |  Save the inscope assets to a file |
|    | --quiet | Disable command-line output. |
| -ho | --hostnames-only | When handling URLs, output only their hostnames instead of the full URLs |
|  | --version | Show the installed version |
|_______________|_____________________________| _____________________________________ |

list example:
```javascript
example.com
dev.example.com
1.dev.example.com
2.dev.example.com
ads.example.com
192.168.1.10
192.168.2.10
192.168.2.8
2001:db8:0000:0000:0000:0000:0000:0001
2001:db8:0000:0000:0000:0000:0000:0002
2001:db8::3
2001:db9:0000:0000:0000:0000:0000:0004
2001:db9::5
http://db123.mycompany.ec2.amazonaws.com/path/to/stuff
http://db123.someothercompany.ec2.amazonaws.com/path/to/stuff
```

Custom .inscope file example:
```javascript
# This is a comment!
# Wildcards
*.example.com
*.sub.domain.example.com
amzn*.domain.example.com

# IPv4 address
192.168.2.10

# IPv4 CIDR range
192.168.1.0/24

# IPv6 addresses
FE80:0000:0000:0000:0202:B3FF:FE1E:8329
FE80::0202:B3FF:FE1E:8329

# IPv6 CIDR range
2001:DB8::/32

# Regex
^\w+:\/\/db[0-9][0-9][0-9]\.mycompany\.ec2\.amazonaws\.com.*$

# Nmap octet ranges
192.168.100-104.1
192.168.200.0-255
192.168.105-107,109.1
```

Custom .noscope file example:
```javascript
community.example.com
thirdparty.example.com
*.thirdparty.example.com
dev.*.example.com
192.168.2.8
FE80::0202:B3FF:FE1E:8330
```

### Wildcards vs Regex
Regex scopes are matched against the entire string that is given as a target, from start to finish, whereas wildcard scopes are only matched against hosts (IPv4s, IPv6s, and URL hosts). Also note that regex scopes aren't affected by --explicit-level settings.

## :heart: Special thank you
This project was inspired by the [yeswehack_vdp_finder](https://github.com/yeswehack/yeswehack_vdp_finder)

## 📄 License
All of the code on this repository is licensed under the *GNU Affero General Public License v3*. A copy can be seen as `LICENSE` on this repository.

The library `golang.org/x/net/publicsuffix`, used within this project is licensed with [BSD-3-Clause](https://pkg.go.dev/golang.org/x/net/publicsuffix?tab=licenses).
