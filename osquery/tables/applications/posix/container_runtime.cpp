/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "container_runtime.h"

#include <cctype>
#include <set>
#include <sstream>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/core/flags.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

namespace pt = boost::property_tree;
namespace local = boost::asio::local;

DECLARE_string(docker_socket);

namespace osquery {
namespace tables {

namespace {

struct RuntimeEndpoint {
  std::string runtime;
  std::string socket_path;
  bool docker_compatible;
};

Status readJson(const std::string& json, pt::ptree& tree) {
  std::string trimmed = json;
  trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
  if (trimmed.empty()) {
    tree.clear();
    return Status::success();
  }

  try {
    std::istringstream stream(json);
    pt::read_json(stream, tree);
  } catch (const pt::ptree_error& error) {
    return Status::failure(std::string("Invalid container runtime JSON: ") +
                           error.what());
  }

  return Status::success();
}

std::string stringValue(const pt::ptree& tree, const std::string& path) {
  auto value = tree.get_optional<std::string>(path);
  return value.value_or(std::string());
}

std::string firstString(const pt::ptree& tree,
                        std::initializer_list<std::string> paths) {
  for (const auto& path : paths) {
    auto value = stringValue(tree, path);
    if (!value.empty()) {
      return value;
    }
  }
  return {};
}

std::string normalizeRuntime(const std::string& runtime) {
  std::string normalized;
  normalized.reserve(runtime.size());
  for (char character : runtime) {
    normalized.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
  }

  if (normalized.find("cri-o") != std::string::npos || normalized == "crio") {
    return kContainerRuntimeCrio;
  }
  if (normalized.find("containerd") != std::string::npos) {
    return kContainerRuntimeContainerd;
  }
  if (normalized.find("podman") != std::string::npos) {
    return kContainerRuntimePodman;
  }
  if (normalized.find("docker") != std::string::npos) {
    return kContainerRuntimeDocker;
  }
  return normalized;
}

std::string runtimeDisplayName(const std::string& runtime) {
  if (runtime == kContainerRuntimeDocker) {
    return "Docker";
  }
  if (runtime == kContainerRuntimePodman) {
    return "Podman";
  }
  if (runtime == kContainerRuntimeContainerd) {
    return "containerd";
  }
  if (runtime == kContainerRuntimeCrio) {
    return "CRI-O";
  }
  return runtime;
}

std::string stripAlgorithmPrefix(const std::string& value) {
  constexpr char kSha256Prefix[] = "sha256:";
  if (boost::starts_with(value, kSha256Prefix)) {
    return value.substr(sizeof(kSha256Prefix) - 1);
  }
  return value;
}

Status runtimeHttpGet(const std::string& socket_path,
                      const std::string& uri,
                      std::string& body) {
  try {
    local::stream_protocol::endpoint endpoint(socket_path);
    local::stream_protocol::iostream stream(endpoint);
    if (!stream) {
      return Status::failure("Unable to connect to runtime socket " +
                             socket_path + ": " + stream.error().message());
    }

    stream << "GET " << uri
           << " HTTP/1.0\r\nAccept: application/json\r\nConnection: "
              "close\r\n\r\n"
           << std::flush;

    std::string status_line;
    std::getline(stream, status_line);
    if (!stream) {
      return Status::failure("Empty runtime API response for " + uri);
    }

    std::string status_code;
    std::istringstream status_stream(status_line);
    std::string http_version;
    status_stream >> http_version >> status_code;
    if (status_code.size() != 3 || status_code[0] != '2') {
      stream.close();
      return Status::failure("Runtime API request failed for " + uri + ": " +
                             status_line);
    }

    std::string header;
    while (std::getline(stream, header)) {
      if (!header.empty() && header.back() == '\r') {
        header.pop_back();
      }
      if (header.empty()) {
        break;
      }
    }

    std::ostringstream body_stream;
    body_stream << stream.rdbuf();
    body = body_stream.str();
    stream.close();
  } catch (const std::exception& error) {
    return Status::failure(std::string("Runtime API error: ") + error.what());
  }

  return Status::success();
}

std::vector<RuntimeEndpoint> runtimeEndpoints() {
  return {
      {kContainerRuntimeDocker, FLAGS_docker_socket, true},
      {kContainerRuntimePodman, "/run/podman/podman.sock", true},
      {kContainerRuntimePodman, "/run/user/0/podman/podman.sock", true},
      {kContainerRuntimeContainerd, "/run/containerd/containerd.sock", false},
      {kContainerRuntimeCrio, "/run/crio/crio.sock", false},
  };
}

std::set<std::string> equalityConstraints(
    QueryContext& context, std::initializer_list<std::string> columns) {
  std::set<std::string> values;
  for (const auto& column : columns) {
    if (context.constraints.count(column) > 0 &&
        context.constraints[column].exists(EQUALS)) {
      auto column_values = context.constraints[column].getAll(EQUALS);
      values.insert(column_values.begin(), column_values.end());
    }
  }
  return values;
}

std::vector<RuntimeEndpoint> endpointsFromContext(QueryContext& context) {
  auto sockets = equalityConstraints(context, {"socket_path", "endpoint"});
  if (sockets.empty()) {
    return runtimeEndpoints();
  }

  auto runtimes = equalityConstraints(context, {"runtime", "runtime_type"});
  auto runtime = runtimes.size() == 1 ? *runtimes.begin() : "docker";
  auto canonical_runtime = normalizeRuntime(runtime);

  std::vector<RuntimeEndpoint> endpoints;
  for (const auto& socket : sockets) {
    endpoints.push_back({canonical_runtime, socket, true});
  }
  return endpoints;
}

void addSocketOnlyRuntimeRow(const RuntimeEndpoint& endpoint,
                             QueryData& results) {
  Row row;
  auto status = parseContainerRuntimeInfo(endpoint.runtime, "{}", "{}", row);
  if (!status.ok()) {
    return;
  }
  row["endpoint"] = endpoint.socket_path;
  row["socket_path"] = endpoint.socket_path;
  row["socket"] = endpoint.socket_path;
  row["status"] = "socket_available";
  row["running"] = INTEGER(1);
  results.push_back(std::move(row));
}

std::string firstArrayString(const pt::ptree& tree,
                             std::initializer_list<std::string> paths) {
  for (const auto& path : paths) {
    auto child = tree.get_child_optional(path);
    if (!child || child->empty()) {
      continue;
    }
    std::string value;
    for (const auto& item : *child) {
      auto item_value = item.second.data();
      if (item_value.empty()) {
        item_value = firstString(item.second, {"name", "tag", "digest"});
      }
      if (item_value.empty()) {
        continue;
      }
      if (!value.empty()) {
        value += ",";
      }
      value += item_value;
    }
    if (!value.empty()) {
      return value;
    }
  }
  return {};
}

void appendLayerList(const pt::ptree& payload,
                     const std::string& path,
                     std::vector<std::string>& layers) {
  if (!layers.empty()) {
    return;
  }

  auto array = payload.get_child_optional(path);
  if (!array) {
    return;
  }

  for (const auto& item : *array) {
    if (!item.second.data().empty()) {
      layers.push_back(item.second.data());
      continue;
    }

    auto digest = firstString(
        item.second, {"digest", "DiffDigest", "diff_digest", "id", "chain_id"});
    if (!digest.empty()) {
      layers.push_back(digest);
    }
  }
}

} // namespace

Status parseContainerRuntimeInfo(const std::string& expected_runtime,
                                 const std::string& version_json,
                                 const std::string& info_json,
                                 Row& row) {
  pt::ptree version;
  pt::ptree info;

  auto status = readJson(version_json, version);
  if (!status.ok()) {
    return status;
  }
  status = readJson(info_json, info);
  if (!status.ok()) {
    return status;
  }

  auto runtime = normalizeRuntime(expected_runtime);
  if (runtime.empty()) {
    runtime = normalizeRuntime(
        firstString(version, {"runtimeName", "RuntimeName", "name"}));
  }
  if (runtime.empty()) {
    runtime = normalizeRuntime(firstString(info, {"runtime", "Runtime"}));
  }

  auto version_value = firstString(version,
                                   {"runtimeVersion",
                                    "Version",
                                    "Server.Version",
                                    "Server.version",
                                    "Client.Version",
                                    "version.Version",
                                    "version.version"});
  if (version_value.empty()) {
    version_value = firstString(
        info, {"ServerVersion", "serverVersion", "version.Version"});
  }

  row.clear();
  row["runtime"] = runtime;
  row["runtime_type"] = runtime;
  row["runtime_name"] = runtime;
  row["name"] = runtimeDisplayName(runtime);
  row["display_name"] = runtimeDisplayName(runtime);
  row["version"] = version_value;
  row["runtime_version"] = firstString(version, {"runtimeVersion"});
  if (row["runtime_version"].empty()) {
    row["runtime_version"] = version_value;
  }
  row["api_version"] = firstString(version,
                                   {"runtimeApiVersion",
                                    "ApiVersion",
                                    "APIVersion",
                                    "Server.ApiVersion",
                                    "Server.APIVersion",
                                    "Client.ApiVersion",
                                    "Client.APIVersion",
                                    "version.APIVersion",
                                    "version.apiVersion"});
  row["min_api_version"] =
      firstString(version, {"MinAPIVersion", "MinApiVersion"});
  row["spec_version"] = firstString(version, {"version"});
  row["git_commit"] = firstString(version,
                                  {"GitCommit",
                                   "gitCommit",
                                   "Server.GitCommit",
                                   "Client.GitCommit",
                                   "version.GitCommit"});
  row["go_version"] = firstString(version,
                                  {"GoVersion",
                                   "goVersion",
                                   "Server.GoVersion",
                                   "Client.GoVersion",
                                   "version.GoVersion"});
  row["os"] = firstString(version, {"Os", "OS", "Server.Os", "Client.Os"});
  if (row["os"].empty()) {
    row["os"] = firstString(info, {"OSType", "osType", "host.os"});
  }
  row["arch"] = firstString(
      version, {"Arch", "Architecture", "Server.Arch", "Client.Arch"});
  if (row["arch"].empty()) {
    row["arch"] =
        firstString(info, {"Architecture", "architecture", "host.arch"});
  }
  row["kernel_version"] =
      firstString(info, {"KernelVersion", "kernelVersion", "host.kernel"});
  if (row["kernel_version"].empty()) {
    row["kernel_version"] = firstString(version, {"KernelVersion"});
  }
  row["oci_runtime"] = firstString(
      info, {"DefaultRuntime", "defaultRuntime", "host.ociRuntime.name"});
  row["storage_driver"] =
      firstString(info, {"Driver", "storageDriver", "store.graphDriverName"});
  row["cgroup_driver"] =
      firstString(info, {"CgroupDriver", "cgroupDriver", "host.cgroupManager"});
  row["storage_root"] =
      firstString(info, {"DockerRootDir", "dockerRootDir", "store.graphRoot"});
  row["root_dir"] = row["storage_root"];
  row["id"] = firstString(info, {"ID", "Id", "id"});
  row["hostname"] = firstString(info, {"Name", "name", "host.hostname"});
  row["endpoint"] = "";
  row["socket_path"] = "";
  row["socket"] = "";
  row["status"] = version_value.empty() ? "unknown" : "ready";
  row["running"] = version_value.empty() ? "0" : "1";

  if (runtime.empty() && version_value.empty()) {
    return Status::failure("Unable to determine container runtime identity");
  }

  return Status::success();
}

Status parseContainerImageLayers(const std::string& runtime,
                                 const std::string& image_id,
                                 const std::string& inspect_json,
                                 QueryData& rows) {
  pt::ptree payload;
  auto status = readJson(inspect_json, payload);
  if (!status.ok()) {
    return status;
  }

  auto canonical_runtime = normalizeRuntime(runtime);
  auto canonical_image_id = image_id;
  if (canonical_image_id.empty()) {
    canonical_image_id =
        firstString(payload, {"Id", "id", "status.id", "image.id"});
  }

  std::vector<std::string> diff_layers;
  appendLayerList(payload, "RootFS.Layers", diff_layers);
  appendLayerList(payload, "rootfs.diff_ids", diff_layers);
  appendLayerList(payload, "info.imageSpec.rootfs.diff_ids", diff_layers);
  appendLayerList(payload, "info.runtimeSpec.rootfs.diff_ids", diff_layers);

  std::vector<std::string> chain_layers;
  appendLayerList(payload, "status.layers", chain_layers);
  appendLayerList(payload, "layers", chain_layers);

  const auto& layers = diff_layers.empty() ? chain_layers : diff_layers;
  auto tags = firstArrayString(
      payload, {"RepoTags", "repoTags", "status.repoTags", "status.RepoTags"});

  for (size_t index = 0; index < layers.size(); ++index) {
    const auto& layer = layers[index];
    auto layer_hex = stripAlgorithmPrefix(layer);
    Row row;
    row["runtime"] = canonical_runtime;
    row["runtime_type"] = canonical_runtime;
    row["runtime_name"] = canonical_runtime;
    row["id"] = stripAlgorithmPrefix(canonical_image_id);
    row["image_id"] = row["id"];
    row["image"] = tags;
    row["image_name"] = tags;
    row["tags"] = tags;
    auto first_tag_end = tags.find(',');
    if (first_tag_end != std::string::npos) {
      row["image"] = tags.substr(0, first_tag_end);
    }
    row["image_name"] = row["image"];
    row["layer_order"] = INTEGER(static_cast<int>(index + 1));
    row["layer_id"] = layer_hex;
    row["digest"] = layer;
    row["layer_digest"] = layer;
    row["diff_id"] = diff_layers.empty() ? "" : diff_layers[index];
    if (!chain_layers.empty() && index < chain_layers.size()) {
      row["chain_id"] = stripAlgorithmPrefix(chain_layers[index]);
    } else {
      row["chain_id"] = "";
    }
    row["size_bytes"] = "";
    row["size"] = "";
    row["media_type"] = "";
    rows.push_back(std::move(row));
  }

  return Status::success();
}

QueryData genContainerRuntimeInfo(QueryContext& context) {
  QueryData results;

  for (const auto& endpoint : endpointsFromContext(context)) {
    auto allowed = equalityConstraints(context, {"runtime", "runtime_type"});
    std::set<std::string> normalized_allowed;
    for (const auto& value : allowed) {
      normalized_allowed.insert(normalizeRuntime(value));
    }
    if (!normalized_allowed.empty() &&
        normalized_allowed.count(endpoint.runtime) == 0) {
      continue;
    }

    if (!endpoint.docker_compatible) {
      if (pathExists(endpoint.socket_path).ok()) {
        addSocketOnlyRuntimeRow(endpoint, results);
      }
      continue;
    }

    std::string version_json;
    auto status =
        runtimeHttpGet(endpoint.socket_path, "/version", version_json);
    if (!status.ok()) {
      VLOG(1) << status.what();
      if (pathExists(endpoint.socket_path).ok() &&
          (endpoint.runtime == kContainerRuntimeContainerd ||
           endpoint.runtime == kContainerRuntimeCrio)) {
        addSocketOnlyRuntimeRow(endpoint, results);
      }
      continue;
    }

    std::string info_json;
    status = runtimeHttpGet(endpoint.socket_path, "/info", info_json);
    if (!status.ok()) {
      VLOG(1) << status.what();
      info_json = "{}";
    }

    Row row;
    status = parseContainerRuntimeInfo(
        endpoint.runtime, version_json, info_json, row);
    if (!status.ok()) {
      VLOG(1) << status.what();
      continue;
    }
    row["endpoint"] = endpoint.socket_path;
    row["socket_path"] = endpoint.socket_path;
    row["socket"] = endpoint.socket_path;
    results.push_back(std::move(row));
  }

  return results;
}

QueryData genContainerImageLayers(QueryContext& context) {
  QueryData results;

  auto requested_ids = equalityConstraints(context, {"id", "image_id"});
  for (const auto& endpoint : endpointsFromContext(context)) {
    if (!endpoint.docker_compatible) {
      continue;
    }

    std::vector<std::string> image_ids;
    if (!requested_ids.empty()) {
      for (const auto& image_id : requested_ids) {
        image_ids.push_back(stripAlgorithmPrefix(image_id));
      }
    } else {
      std::string images_json;
      auto status =
          runtimeHttpGet(endpoint.socket_path, "/images/json", images_json);
      if (!status.ok()) {
        VLOG(1) << status.what();
        continue;
      }

      pt::ptree images;
      status = readJson(images_json, images);
      if (!status.ok()) {
        VLOG(1) << status.what();
        continue;
      }

      for (const auto& image : images) {
        auto image_id = firstString(image.second, {"Id", "id"});
        if (!image_id.empty()) {
          image_ids.push_back(stripAlgorithmPrefix(image_id));
        }
      }
    }

    for (const auto& image_id : image_ids) {
      std::string inspect_json;
      auto status = runtimeHttpGet(
          endpoint.socket_path, "/images/" + image_id + "/json", inspect_json);
      if (!status.ok()) {
        VLOG(1) << status.what();
        continue;
      }

      QueryData image_rows;
      status = parseContainerImageLayers(
          endpoint.runtime, image_id, inspect_json, image_rows);
      if (!status.ok()) {
        VLOG(1) << status.what();
        continue;
      }
      results.insert(results.end(), image_rows.begin(), image_rows.end());
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
