// SPDX-License-Identifier: GPL-2.0-or-later
//
// Services module — optional network services provided by dnsmasq.
//
// Currently contains the TFTP server for PXE/network boot support,
// gated by the `tftp` Cargo feature (matching C `HAVE_TFTP`).

/// TFTP server module — read-only TFTP for PXE/network boot.
#[cfg(feature = "tftp")]
pub mod tftp;
