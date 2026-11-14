/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

namespace osquery {
namespace tables {

// Extracts the unit type (the suffix of the unit id, e.g. "service",
// "socket", "timer") from identifiers such as "sshd.service".
// Returns an empty string when the id has no suffix.
std::string getUnitType(const std::string& id);

} // namespace tables
} // namespace osquery
