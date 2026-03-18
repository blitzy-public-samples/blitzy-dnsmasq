// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Configuration module root — declares sub-modules for the config subsystem.
// Maps to C `src/config.h` and `src/option.c`, providing compile-time constants,
// feature flag detection, configuration file parsing, and CLI argument processing.

pub mod cli;
pub mod constants;
pub mod features;
