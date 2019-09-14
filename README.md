# acme-mock

A server implementation of the [ACME protocol][RFC 8555] performing no validations.

## Motivation

I make heavy use of ACME in [ansible] playbooks. Occasionally, I test
these playbooks in virtual machines. Unfortunately, these virtual
machines are incapable of completing ACME challenges and therefore don't
receive any certificates from configured ACME servers. Without these
certificates many daemons will refuse to start causing failures of
ansible tasks.

For this reason, I implemented a simple ACME server which doesn't
perform any validations and always signs the given certificate signing
requests.

## Status

This is a horrible hack, I didn't read the entire RFC and only
implemented the parts needed to make [acme-tiny][acme-tiny github] work.

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
