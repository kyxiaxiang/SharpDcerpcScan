# SharpDcerpcScan


---

SharpDcerpcScan is a .NET 4.0 tool for probing remote Windows host information using DCERPC and NTLMSSP protocols. This tool is inspired by the Python project [Dcerpc_Find_OSInfo](https://github.com/komomon/Dcerpc_Find_OSInfo) created by [Komomon](https://github.com/komomon).

## Features

- **Remote Host Information Retrieval**: Gather detailed OS information from remote Windows hosts.
- **IP Range Scanning**: Supports single IP, IP ranges, and IP lists from a file.
- **Multi-threading**: Speed up the scanning process with multi-threading.
- **Output Logging**: Save the results to a specified log file.

## Usage

```sh
SharpDcerpcScan.exe -i <IP Address/Range/File> [-t <threads>] [-o <Output File>]
```

### Parameters

- `-i, --ip`: **Required**. IP Address, IP Range (e.g., `192.168.1.1-192.168.2.2`), or a file containing a list of IP addresses.
- `-t, --threads`: Number of threads to use for scanning. Default is 20.
- `-o, --output`: Output file to save the results. Default is `log.txt`.

### Examples

- Scan a single IP:
  ```sh
  SharpDcerpcScan.exe -i 192.168.22.1
  ```

- Scan an IP range:
  ```sh
  SharpDcerpcScan.exe -i 192.168.1.1-192.168.1.255
  ```

- Scan IPs from a file:
  ```sh
  SharpDcerpcScan.exe -i ip_list.txt
  ```

## Compilation

To compile the project, open it in Visual Studio and build it as a .NET Framework 4.0 application.

## Output

The output is saved in the specified log file (default is `log.txt`). Each entry includes the IP address and retrieved OS information such as OS version, NetBIOS domain name, DNS domain name, DNS computer name, and DNS tree name.

## Example Output

```
[*] 192.168.22.1
    [->] OS_Verison : Windows Version 10.0 Build 22621 x64
    [->] NetBIOS_domain_name : EXAMPLE-NB
    [->] DNS_domain_name : example.local
    [->] DNS_computer_name : example-computer
    [->] DNS_tree_name : example-tree

[*] 192.168.31.186
    [->] OS_Verison : Windows Version 10.0 Build 19041 x64
    [->] NetBIOS_domain_name : EXAMPLE-NB2
    [->] DNS_domain_name : example2.local
    [->] DNS_computer_name : example2-computer
    [->] DNS_tree_name : example2-tree
```

## Acknowledgements

This project is inspired by and adapted from the Python project [Dcerpc_Find_OSInfo](https://github.com/komomon/Dcerpc_Find_OSInfo) by [Komomon](https://github.com/komomon). Special thanks for providing the initial implementation and inspiration.

---
