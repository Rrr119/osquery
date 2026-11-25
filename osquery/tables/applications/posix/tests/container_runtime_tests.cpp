/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <atomic>
#include <map>
#include <thread>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <osquery/tables/applications/posix/container_runtime.h>

namespace osquery {
namespace tables {

QueryData genContainerRuntimeInfo(QueryContext& context);
QueryData genContainerImageLayers(QueryContext& context);

namespace {

class MockRuntimeSocket {
 public:
  MockRuntimeSocket(std::string path, std::map<std::string, std::string> routes)
      : path_(std::move(path)), routes_(std::move(routes)) {
    ::unlink(path_.c_str());
    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    EXPECT_GE(fd_, 0);

    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    ::strncpy(address.sun_path, path_.c_str(), sizeof(address.sun_path) - 1);

    EXPECT_EQ(
        ::bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    EXPECT_EQ(::listen(fd_, 8), 0);
    thread_ = std::thread([this]() { serve(); });
  }

  ~MockRuntimeSocket() {
    stop_ = true;
    ::shutdown(fd_, SHUT_RDWR);
    if (thread_.joinable()) {
      thread_.join();
    }
    ::close(fd_);
    ::unlink(path_.c_str());
  }

 private:
  void serve() {
    while (!stop_) {
      int client = ::accept(fd_, nullptr, nullptr);
      if (client < 0) {
        if (stop_) {
          return;
        }
        continue;
      }

      char buffer[4096] = {};
      auto received = ::recv(client, buffer, sizeof(buffer) - 1, 0);
      if (received > 0) {
        std::string request(buffer, static_cast<size_t>(received));
        auto line_end = request.find("\r\n");
        auto first_line = request.substr(0, line_end);
        auto first_space = first_line.find(' ');
        auto second_space = first_line.find(' ', first_space + 1);
        auto target =
            first_line.substr(first_space + 1, second_space - first_space - 1);

        std::string status = "200 OK";
        std::string body;
        auto route = routes_.find(target);
        if (route == routes_.end()) {
          status = "404 Not Found";
          body = "{}";
        } else {
          body = route->second;
        }

        std::string response = "HTTP/1.0 " + status +
                               "\r\nContent-Type: application/json"
                               "\r\nContent-Length: " +
                               std::to_string(body.size()) +
                               "\r\nConnection: close\r\n\r\n" + body;
        ::send(client, response.data(), response.size(), 0);
      }
      ::close(client);
    }
  }

  std::string path_;
  std::map<std::string, std::string> routes_;
  int fd_{-1};
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

} // namespace

class ContainerRuntimeTests : public ::testing::Test {};

TEST_F(ContainerRuntimeTests, docker_runtime_and_layers) {
  const std::string version = R"JSON({
    "Version": "27.3.1",
    "ApiVersion": "1.46",
    "MinAPIVersion": "1.24",
    "GitCommit": "de9f1a",
    "GoVersion": "go1.22.7",
    "Os": "linux",
    "Arch": "amd64"
  })JSON";

  const std::string info = R"JSON({
    "ID": "docker-engine-id",
    "Driver": "overlay2",
    "CgroupDriver": "systemd",
    "DockerRootDir": "/var/lib/docker",
    "Name": "docker-host",
    "KernelVersion": "6.8.0-generic",
    "DefaultRuntime": "runc"
  })JSON";

  Row runtime;
  ASSERT_TRUE(parseContainerRuntimeInfo("docker", version, info, runtime).ok());
  EXPECT_EQ(runtime.at("runtime"), "docker");
  EXPECT_EQ(runtime.at("runtime_type"), "docker");
  EXPECT_EQ(runtime.at("name"), "Docker");
  EXPECT_EQ(runtime.at("version"), "27.3.1");
  EXPECT_EQ(runtime.at("api_version"), "1.46");
  EXPECT_EQ(runtime.at("min_api_version"), "1.24");
  EXPECT_EQ(runtime.at("git_commit"), "de9f1a");
  EXPECT_EQ(runtime.at("go_version"), "go1.22.7");
  EXPECT_EQ(runtime.at("os"), "linux");
  EXPECT_EQ(runtime.at("arch"), "amd64");
  EXPECT_EQ(runtime.at("kernel_version"), "6.8.0-generic");
  EXPECT_EQ(runtime.at("oci_runtime"), "runc");
  EXPECT_EQ(runtime.at("storage_driver"), "overlay2");
  EXPECT_EQ(runtime.at("cgroup_driver"), "systemd");
  EXPECT_EQ(runtime.at("storage_root"), "/var/lib/docker");
  EXPECT_EQ(runtime.at("root_dir"), "/var/lib/docker");
  EXPECT_EQ(runtime.at("hostname"), "docker-host");
  EXPECT_EQ(runtime.at("running"), "1");

  const std::string inspect = R"JSON({
    "Id": "sha256:image0123456789abcdef",
    "RepoTags": ["alpine:3.20", "alpine:latest"],
    "RootFS": {
      "Type": "layers",
      "Layers": [
        "sha256:base0000000000000000",
        "sha256:top1111111111111111"
      ]
    }
  })JSON";

  QueryData layers;
  ASSERT_TRUE(parseContainerImageLayers("docker", "", inspect, layers).ok());
  ASSERT_EQ(layers.size(), 2U);

  EXPECT_EQ(layers[0].at("runtime"), "docker");
  EXPECT_EQ(layers[0].at("id"), "image0123456789abcdef");
  EXPECT_EQ(layers[0].at("image_id"), "image0123456789abcdef");
  EXPECT_EQ(layers[0].at("layer_order"), "1");
  EXPECT_EQ(layers[0].at("layer_id"), "base0000000000000000");
  EXPECT_EQ(layers[0].at("digest"), "sha256:base0000000000000000");
  EXPECT_EQ(layers[0].at("diff_id"), "sha256:base0000000000000000");
  EXPECT_EQ(layers[0].at("tags"), "alpine:3.20,alpine:latest");
  EXPECT_EQ(layers[0].at("image"), "alpine:3.20");

  EXPECT_EQ(layers[1].at("layer_order"), "2");
  EXPECT_EQ(layers[1].at("layer_id"), "top1111111111111111");
}

TEST_F(ContainerRuntimeTests, podman_native_payload) {
  const std::string version = R"JSON({
    "Client": {
      "APIVersion": "5.3.0",
      "Version": "5.3.0",
      "GoVersion": "go1.23.3",
      "GitCommit": "podman-commit",
      "Os": "linux",
      "Arch": "arm64"
    },
    "Server": {
      "APIVersion": "5.3.0",
      "Version": "5.3.0",
      "GoVersion": "go1.23.3",
      "GitCommit": "podman-commit",
      "Os": "linux",
      "Arch": "arm64"
    }
  })JSON";

  const std::string info = R"JSON({
    "host": {
      "arch": "arm64",
      "kernel": "6.11.0",
      "os": "linux",
      "cgroupManager": "systemd",
      "hostname": "podman-host",
      "ociRuntime": {"name": "crun"}
    },
    "store": {
      "graphDriverName": "overlay",
      "graphRoot": "/var/lib/containers/storage"
    }
  })JSON";

  Row runtime;
  ASSERT_TRUE(parseContainerRuntimeInfo("podman", version, info, runtime).ok());
  EXPECT_EQ(runtime.at("runtime"), "podman");
  EXPECT_EQ(runtime.at("name"), "Podman");
  EXPECT_EQ(runtime.at("version"), "5.3.0");
  EXPECT_EQ(runtime.at("api_version"), "5.3.0");
  EXPECT_EQ(runtime.at("go_version"), "go1.23.3");
  EXPECT_EQ(runtime.at("git_commit"), "podman-commit");
  EXPECT_EQ(runtime.at("arch"), "arm64");
  EXPECT_EQ(runtime.at("kernel_version"), "6.11.0");
  EXPECT_EQ(runtime.at("cgroup_driver"), "systemd");
  EXPECT_EQ(runtime.at("oci_runtime"), "crun");
  EXPECT_EQ(runtime.at("storage_driver"), "overlay");
  EXPECT_EQ(runtime.at("storage_root"), "/var/lib/containers/storage");

  const std::string inspect = R"JSON({
    "Id": "sha256:podmanimage",
    "RootFS": {
      "Layers": ["sha256:podbase", "sha256:podmiddle", "sha256:podtop"]
    }
  })JSON";

  QueryData layers;
  ASSERT_TRUE(
      parseContainerImageLayers("podman", "podmanimage", inspect, layers).ok());
  ASSERT_EQ(layers.size(), 3U);
  EXPECT_EQ(layers[0].at("runtime_type"), "podman");
  EXPECT_EQ(layers[0].at("id"), "podmanimage");
  EXPECT_EQ(layers[0].at("layer_order"), "1");
  EXPECT_EQ(layers[0].at("layer_id"), "podbase");
  EXPECT_EQ(layers[1].at("layer_order"), "2");
  EXPECT_EQ(layers[1].at("layer_id"), "podmiddle");
  EXPECT_EQ(layers[2].at("layer_order"), "3");
  EXPECT_EQ(layers[2].at("layer_id"), "podtop");
}

TEST_F(ContainerRuntimeTests, crio_cri_payload) {
  const std::string version = R"JSON({
    "version": "v1",
    "runtimeName": "cri-o",
    "runtimeVersion": "1.31.0",
    "runtimeApiVersion": "v1"
  })JSON";

  Row runtime;
  ASSERT_TRUE(parseContainerRuntimeInfo("crio", version, "{}", runtime).ok());
  EXPECT_EQ(runtime.at("runtime"), "crio");
  EXPECT_EQ(runtime.at("name"), "CRI-O");
  EXPECT_EQ(runtime.at("version"), "1.31.0");
  EXPECT_EQ(runtime.at("runtime_version"), "1.31.0");
  EXPECT_EQ(runtime.at("api_version"), "v1");
  EXPECT_EQ(runtime.at("spec_version"), "v1");
  EXPECT_EQ(runtime.at("running"), "1");

  const std::string inspect = R"JSON({
    "status": {
      "id": "sha256:crioimage",
      "repoTags": ["registry.example/app:1.0"],
      "layers": ["sha256:chainbase", "sha256:chaintop"]
    },
    "info": {
      "imageSpec": {
        "rootfs": {
          "type": "layers",
          "diff_ids": ["sha256:diffbase", "sha256:difftop"]
        }
      }
    }
  })JSON";

  QueryData layers;
  ASSERT_TRUE(parseContainerImageLayers("crio", "", inspect, layers).ok());
  ASSERT_EQ(layers.size(), 2U);
  EXPECT_EQ(layers[0].at("runtime"), "crio");
  EXPECT_EQ(layers[0].at("id"), "crioimage");
  EXPECT_EQ(layers[0].at("tags"), "registry.example/app:1.0");
  EXPECT_EQ(layers[0].at("layer_order"), "1");
  EXPECT_EQ(layers[0].at("layer_id"), "diffbase");
  EXPECT_EQ(layers[0].at("diff_id"), "sha256:diffbase");
  EXPECT_EQ(layers[0].at("chain_id"), "chainbase");
  EXPECT_EQ(layers[1].at("layer_order"), "2");
  EXPECT_EQ(layers[1].at("layer_id"), "difftop");
  EXPECT_EQ(layers[1].at("chain_id"), "chaintop");
}

TEST_F(ContainerRuntimeTests, containerd_is_recognized) {
  const std::string version = R"JSON({
    "runtimeName": "containerd",
    "runtimeVersion": "2.0.0",
    "runtimeApiVersion": "v1"
  })JSON";

  Row runtime;
  ASSERT_TRUE(parseContainerRuntimeInfo("", version, "{}", runtime).ok());
  EXPECT_EQ(runtime.at("runtime"), "containerd");
  EXPECT_EQ(runtime.at("name"), "containerd");
  EXPECT_EQ(runtime.at("version"), "2.0.0");

  const std::string inspect = R"JSON({
    "status": {
      "id": "sha256:containerdimage",
      "layers": ["sha256:chainbase", "sha256:chaintop"]
    },
    "info": {
      "imageSpec": {
        "rootfs": {
          "diff_ids": ["sha256:diffbase", "sha256:difftop"]
        }
      }
    }
  })JSON";

  QueryData layers;
  ASSERT_TRUE(
      parseContainerImageLayers("containerd", "", inspect, layers).ok());
  ASSERT_EQ(layers.size(), 2U);
  EXPECT_EQ(layers[0].at("runtime_name"), "containerd");
  EXPECT_EQ(layers[0].at("id"), "containerdimage");
  EXPECT_EQ(layers[0].at("layer_id"), "diffbase");
  EXPECT_EQ(layers[0].at("chain_id"), "chainbase");
}

TEST_F(ContainerRuntimeTests, rejects_invalid_or_unknown_payloads) {
  Row runtime;
  EXPECT_FALSE(
      parseContainerRuntimeInfo("docker", "{not-json", "{}", runtime).ok());
  EXPECT_FALSE(parseContainerRuntimeInfo("", "{}", "{}", runtime).ok());

  QueryData layers;
  EXPECT_FALSE(
      parseContainerImageLayers("docker", "id", "{not-json", layers).ok());
}

TEST_F(ContainerRuntimeTests, table_generators_query_socket_endpoint) {
  const auto socket_path = std::string(testing::TempDir()) + "cr_mock_" +
                           std::to_string(::getpid()) + ".sock";

  const std::string version = R"JSON({
    "Version": "27.3.1",
    "ApiVersion": "1.46",
    "GitCommit": "socket-test"
  })JSON";
  const std::string info = R"JSON({
    "Driver": "overlay2",
    "DockerRootDir": "/var/lib/docker"
  })JSON";
  const std::string images = R"JSON([{"Id": "sha256:socketimage"}])JSON";
  const std::string inspect = R"JSON({
    "Id": "sha256:socketimage",
    "RootFS": {"Layers": ["sha256:socketbase", "sha256:sockettop"]}
  })JSON";

  MockRuntimeSocket server(socket_path,
                           {{"/version", version},
                            {"/info", info},
                            {"/images/json", images},
                            {"/images/socketimage/json", inspect}});

  QueryContext runtime_context;
  runtime_context.constraints["socket_path"].add(
      Constraint(EQUALS, socket_path));
  runtime_context.constraints["runtime"].add(
      Constraint(EQUALS, kContainerRuntimeDocker));

  auto runtime_rows = genContainerRuntimeInfo(runtime_context);
  ASSERT_EQ(runtime_rows.size(), 1U);
  EXPECT_EQ(runtime_rows[0].at("runtime"), "docker");
  EXPECT_EQ(runtime_rows[0].at("version"), "27.3.1");
  EXPECT_EQ(runtime_rows[0].at("storage_driver"), "overlay2");
  EXPECT_EQ(runtime_rows[0].at("socket_path"), socket_path);

  QueryContext layer_context;
  layer_context.constraints["endpoint"].add(Constraint(EQUALS, socket_path));
  layer_context.constraints["runtime"].add(
      Constraint(EQUALS, kContainerRuntimeDocker));

  auto layer_rows = genContainerImageLayers(layer_context);
  ASSERT_EQ(layer_rows.size(), 2U);
  EXPECT_EQ(layer_rows[0].at("id"), "socketimage");
  EXPECT_EQ(layer_rows[0].at("layer_order"), "1");
  EXPECT_EQ(layer_rows[0].at("layer_id"), "socketbase");
  EXPECT_EQ(layer_rows[1].at("layer_order"), "2");
  EXPECT_EQ(layer_rows[1].at("layer_id"), "sockettop");
}

TEST_F(ContainerRuntimeTests, runtime_apis_query_correct_layers) {
  struct RuntimeFixture {
    std::string runtime;
    std::string version;
    std::string info;
    std::string inspect;
    std::string expected_version;
    std::string first_layer;
  };

  const std::vector<RuntimeFixture> fixtures = {
      {"docker",
       R"JSON({"Version":"27.3.1","ApiVersion":"1.46"})JSON",
       R"JSON({"Driver":"overlay2"})JSON",
       R"JSON({"Id":"sha256:multi",
               "RootFS":{"Layers":[
                 "sha256:dockerbase","sha256:dockertop"]}})JSON",
       "27.3.1",
       "dockerbase"},
      {"podman",
       R"JSON({"Version":"5.3.0","ApiVersion":"1.41"})JSON",
       R"JSON({"host":{"arch":"amd64"},
               "store":{"graphDriverName":"overlay"}})JSON",
       R"JSON({"Id":"sha256:multi",
               "RootFS":{"Layers":[
                 "sha256:podbase","sha256:podtop"]}})JSON",
       "5.3.0",
       "podbase"},
      {"containerd",
       R"JSON({"runtimeName":"containerd","runtimeVersion":"2.0.0"})JSON",
       "{}",
       R"JSON({"status":{"id":"sha256:multi",
                         "layers":["sha256:containerdchainbase",
                                   "sha256:containerdchaintop"]},
               "info":{"imageSpec":{"rootfs":{
                 "diff_ids":["sha256:containerddiffbase",
                             "sha256:containerddifftop"]}}}})JSON",
       "2.0.0",
       "containerddiffbase"},
      {"crio",
       R"JSON({"runtimeName":"cri-o","runtimeVersion":"1.31.0"})JSON",
       "{}",
       R"JSON({"status":{"id":"sha256:multi",
                         "layers":["sha256:criochainbase",
                                   "sha256:criochaintop"]},
               "info":{"imageSpec":{"rootfs":{
                 "diff_ids":["sha256:criodiffbase",
                             "sha256:criodifftop"]}}}})JSON",
       "1.31.0",
       "criodiffbase"},
  };

  for (const auto& fixture : fixtures) {
    const auto socket_path = std::string(testing::TempDir()) + "cr_" +
                             fixture.runtime + "_" +
                             std::to_string(::getpid()) + ".sock";
    MockRuntimeSocket server(
        socket_path,
        {{"/version", fixture.version},
         {"/info", fixture.info},
         {"/images/json", R"JSON([{"Id":"sha256:multi"}])JSON"},
         {"/images/multi/json", fixture.inspect}});

    QueryContext runtime_context;
    runtime_context.constraints["socket_path"].add(
        Constraint(EQUALS, socket_path));
    runtime_context.constraints["runtime_type"].add(Constraint(
        EQUALS, fixture.runtime == "crio" ? "cri-o" : fixture.runtime));

    auto runtime_rows = genContainerRuntimeInfo(runtime_context);
    ASSERT_EQ(runtime_rows.size(), 1U) << fixture.runtime;
    EXPECT_EQ(runtime_rows[0].at("runtime"), fixture.runtime);
    EXPECT_EQ(runtime_rows[0].at("runtime_name"), fixture.runtime);
    EXPECT_EQ(runtime_rows[0].at("version"), fixture.expected_version);
    EXPECT_EQ(runtime_rows[0].at("socket"), socket_path);

    QueryContext layer_context;
    layer_context.constraints["endpoint"].add(Constraint(EQUALS, socket_path));
    layer_context.constraints["runtime"].add(
        Constraint(EQUALS, fixture.runtime));

    auto layer_rows = genContainerImageLayers(layer_context);
    ASSERT_EQ(layer_rows.size(), 2U) << fixture.runtime;
    EXPECT_EQ(layer_rows[0].at("runtime"), fixture.runtime);
    EXPECT_EQ(layer_rows[0].at("id"), "multi");
    EXPECT_EQ(layer_rows[0].at("layer_order"), "1");
    EXPECT_EQ(layer_rows[0].at("layer_id"), fixture.first_layer);
    EXPECT_EQ(layer_rows[1].at("layer_order"), "2");
  }
}

} // namespace tables
} // namespace osquery
