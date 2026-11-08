# flaghunter

Point it at a CTF crypto challenge or a packet capture, it runs the whole attack battery, writes up what fell out.

Built on top of [cryptsmith](https://github.com/burrejak22/cryptsmith), which does the actual crypto and pcap work. flaghunter is the analyst that drives it.

## Install

```bash
pip install flaghunter
```

## Use

```bash
flaghunter solve challenge.txt                                  # crypto challenge file
flaghunter pcap capture.pcap                                    # hunt a pcap
flaghunter pcap capture.pcap --pattern "FLAG\{[^}]+\}" --format json
```

## What the pcap hunter does

1. Reassembles TCP streams from the capture.
2. Carves printable strings out of every stream.
3. Hunts tokens matching your pattern (default: 12-char alpha strings, like enrollment keys).
4. Scores every stream for entropy, then runs single-byte XOR, repeating-key XOR, caesar, and layered base64/hex decoding on anything suspicious.
5. Writes a markdown report with stream labels, findings, and decoded candidates.

## What the solver does

Reads a challenge file and runs the battery. Encoding layers, XOR attacks, classical ciphers, hash identification. Ranks everything by english score so the real answer floats to the top.

## Example

A capture where a server checks a 12-character alpha enrollment key, and the key is XOR-obfuscated in the traffic. flaghunter finds the stream, breaks the XOR, hands you the key. That's the shape.

## License

MIT
