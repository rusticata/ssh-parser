![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)
[![LICENSE](https://img.shields.io/badge/License-LGPL%20v2.1-blue.svg)](LICENSE)
[![Build Status](https://github.com/rusticata/ssh-parser/actions/workflows/rust.yml/badge.svg)](https://github.com/rusticata/ssh-parser/actions/workflows/rust.yml)
[![Crates.io Version](https://img.shields.io/crates/v/ssh-parser.svg)](https://crates.io/crates/ssh-parser)

# ssh-parser

## Overview

This crate provides functions to parse the SSH 2.0 protocol packets. It is also
able to recognize older versions of SSH in the identification phase. The main
purpose of ssh-parser is to implement safe protocol analysis in network
monitoring tools such as IDS and thus it is only able to parse unprotected
packets (like the SSH handshake).

## Standards

The following specification are partially implemented:
- [RFC4253](https://tools.ietf.org/html/rfc4253) The Secure Shell (SSH) Transport Layer Protocol
- [RFC4251](https://tools.ietf.org/html/rfc4251) The Secure Shell (SSH) Protocol Architecture
- [RFC4250](https://tools.ietf.org/html/rfc4250) The Secure Shell (SSH) Protocol Assigned Numbers
- [RFC5656](https://tools.ietf.org/html/rfc5656) Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer
- [RFC6239](https://tools.ietf.org/html/rfc6239) Suite B Cryptographic Suites for Secure Shell (SSH)
- [IANA SSH Protocol Parameters](http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml)

## License

This library is licensed under the GNU Lesser General Public License version 2.1, or (at your option) any later version.
