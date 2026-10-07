# flaghunter

Point it at a CTF crypto challenge or a packet capture and it runs a full attack battery for you, then writes up what it found.

Built on [cryptsmith](https://github.com/burrejak22/cryptsmith), which does all the crypto and pcap heavy lifting. flaghunter is the analyst on top.

## Install

```bash
pip install flaghunter
```

## Use

```bash
# throw a crypto challenge file at it
flaghunter solve challenge.txt

# hunt a pcap for enrollment keys, flags, and obfuscated blobs
flaghunter pcap capture.pcap

# custom token pattern, json output
flaghunter pcap capture.pcap --pattern "FLAG\{[^}]+\}" --format json
```

## What the pcap hunter does

1. Reassembles TCP streams from the capture
2. Carves printable strings out of every stream
3. Hunts tokens matching your pattern (default: 12 char alpha strings, like enrollment keys)
4. Scores every stream for entropy, then runs single byte xor, repeating key xor, caesar, and layered base64/hex decoding on anything suspicious
5. Writes a markdown report with stream labels, findings, and decoded candidates

## What the solver does

Reads a challenge file and runs the battery: encoding layers, xor attacks, classical ciphers, hash identification. Ranks everything by english score so the real answer floats to the top.

## Example

Say a capture has a server checking a 12 character alpha enrollment key, and the key is xor obfuscated in the traffic. flaghunter finds the stream, breaks the xor, and hands you the key.

## License

MIT
