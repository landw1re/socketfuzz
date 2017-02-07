# socketfuzz
Simple socket fuzzer
```bash
usage: socketfuzz.py [-h] [-i <ip address>] [-p <port>] [-f <buffer to fuzz>]
                     [--growing-buffer] [-s <size>] [-c <char>]
                     [-n <increment>] [--single] [--rand] [--check-badchars]
                     [-l <buffer location>] [-r <chars to remove>]
                     [-e <EIP value>] [--find-offset]
                     [--locate-space-4-shellcode] [--find-return-addr]
                     [-a <return address>] [--send-exploit]
                     [-x <shellcode file>]

Simple socket fuzzer

optional arguments:
  -h, --help            show this help message and exit
  -i <ip address>       valid IPv4 IP address
  -p <port>             valid TCP port (1 - 65535)
  -f <buffer to fuzz>   input integer of buffer to fuzz. Buffers available to
                        fuzz: 1) pop3_password_buffer
  --growing-buffer      create a growing buffer to send to the service using
                        -s, -c & -n arguments (these are optional arguments -
                        review default values before using though).
  -s <size>             maximum size the buffer should grow to - default is
                        2000
  -c <char>             a single Alphabetic character to be used as the
                        character to fill the buffer with - default is "A"
  -n <increment>        buffer growth increment - default is 200
  --single              send one single string buffer to the service using -s
                        and -c arguments as optional arguments.
  --rand                generate a single random buffer using the
                        pattern_create utility from the Metasploit framework -
                        use the -s argument to specify the size of the buffer
                        to create - the default size is 2000.
  --check-badchars      send a list of ALL possible characters in hex (x00 to
                        xff) to check what characters are bad and let us know
                        what characters to not include in our buffer, return
                        address or shell code. MUST use the -l argument
  -l <buffer location>  location of the buffer offset that overwrote the EIP
                        register after using the --rand command to send a
                        buffer. Use the --find-offset argument with the -s and
                        the -e argument.
  -r <chars to remove>  string of hex chars to remove from the hex list. The
                        string of chars MUST be in hex format and be separated
                        by a comma (e.g. "\x01,\x02,\x03").
  -e <EIP value>        value of the EIP register after using the --rand
                        argument
  --find-offset         find the offset of the value displayed in the EIP
                        register after using the --rand argument. MUST use the
                        -s argument and -e argument
  --locate-space-4-shellcode
                        locate space for shellcode in the buffer being
                        overrun. MUST use the -s argument and -l argument
  --find-return-addr    find a return address to divert execution to our
                        shellcode. MUST use the -l argument and the -a
                        argument
  -a <return address>   return address (in hex format e.g "\x8f\x35\x4a\x5f")
                        to use to divert execution flow back to our shellcode.
                        As an example, the Immunity debugger script mona.py
                        can be used to assist in finding an appropriate return
                        address to use.
  --send-exploit        test exploit and send shellcode. MUST use -l argument,
                        -a argument and -x argument.
  -x <shellcode file>   file containing shellcode string to use. Use a tool
                        like msfvenom to automate the creation of reverse
                        shell shellcode.

Examples of Use:
--------------------------------
Work in progress - examples will be added soon
```
