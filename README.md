# acme-mock

A server implementation of the [ACME protocol][RFC 8555] performing no validations.

## Motivation

I make heavy use of ACME in [ansible][ansible homepage] playbooks.
Occasionally, I test these playbooks in virtual machines. Unfortunately,
these virtual machines are incapable of completing ACME challenges and
therefore don't receive any certificates from configured ACME servers.
Without these certificates many daemons will refuse to start causing
failures of ansible tasks.

For this reason, I implemented a simple ACME server which doesn't
perform any validations and always signs the given certificate signing
requests.

## Status

This is a horrible hack, I didn't read the entire RFC and only
implemented the parts needed to make [acme-tiny][acme-tiny github] work.

## Usage

This software has no external dependencies and can be installed using:

	$ go get github.com/nmeum/acme-mock

Since ACME requires use of HTTPS, a TLS certificate is required for using
this software. A bogus certificate can be generated with `openssl`:

	$ yes "" | openssl req -x509 -nodes -newkey rsa:4096 \
		-keyout key.pem -out cert.pem

The generated TLS certificate and key need to be passed to `acme-mock`.
Additionally, the TLS certificate needs to be added to the certificate
store of the virtual machine. Afterwards, the ACME client needs to be
configured to use the `acme-mock` directory. The URL of the directory
resource depends on the address parameter, it defaults to
`https://localhost/directory`. The certificate, used for processing
certificate signing requests, is generated on startup.

## License

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

[RFC 8555]: https://tools.ietf.org/html/rfc8555
[ansible homepage]: https://ansible.com/
[acme-tiny github]: https://github.com/diafygi/acme-tiny
