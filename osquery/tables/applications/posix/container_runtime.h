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

#include <osquery/core/tables.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {

inline constexpr char kContainerRuntimeDocker[] = "docker";
inline constexpr char kContainerRuntimePodman[] = "podman";
inline constexpr char kContainerRuntimeContainerd[] = "containerd";
inline constexpr char kContainerRuntimeCrio[] = "crio";

/**
 * @brief Parse version and engine/info payloads from a runtime.
 *
 * The parser accepts the Docker Engine API shape, Podman's Docker-compatible
 * and native info shapes, and the CRI version/info shape used by containerd
 * and CRI-O.
 */
Status parseContainerRuntimeInfo(const std::string& expected_runtime,
                                 const std::string& version_json,
                                 const std::string& info_json,
                                 Row& row);

/**
 * @brief Parse image layer metadata.
 *
 * Supported payloads are Docker/Podman image inspect JSON and CRI image status
 * JSON from containerd or CRI-O. Layer order is normalized to start at 1 for
 * the base layer.
 */
Status parseContainerImageLayers(const std::string& runtime,
                                 const std::string& image_id,
                                 const std::string& inspect_json,
                                 QueryData& rows);

} // namespace tables
} // namespace osquery
