/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for container_runtime_info and
// container_runtimes.

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ContainerRuntimeInfoTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ContainerRuntimeInfoTest, test_sanity) {
  for (const auto& table_name :
       {"container_runtime_info", "container_runtimes", "container_runtime"}) {
    QueryData data = execute_query(std::string("select * from ") + table_name);
    if (data.empty()) {
      continue;
    }

    ValidationMap row_map = {
        {"runtime", NonEmptyString},
        {"runtime_type", NonEmptyString},
        {"runtime_name", NonEmptyString},
        {"name", NonEmptyString},
        {"display_name", NormalType | EmptyOk},
        {"version", NormalType | EmptyOk},
        {"runtime_version", NormalType | EmptyOk},
        {"api_version", NormalType | EmptyOk},
        {"min_api_version", NormalType | EmptyOk},
        {"spec_version", NormalType | EmptyOk},
        {"git_commit", NormalType | EmptyOk},
        {"go_version", NormalType | EmptyOk},
        {"os", NormalType | EmptyOk},
        {"arch", NormalType | EmptyOk},
        {"kernel_version", NormalType | EmptyOk},
        {"oci_runtime", NormalType | EmptyOk},
        {"storage_driver", NormalType | EmptyOk},
        {"cgroup_driver", NormalType | EmptyOk},
        {"storage_root", NormalType | EmptyOk},
        {"root_dir", NormalType | EmptyOk},
        {"id", NormalType | EmptyOk},
        {"hostname", NormalType | EmptyOk},
        {"endpoint", NormalType | EmptyOk},
        {"socket_path", NormalType | EmptyOk},
        {"socket", NormalType | EmptyOk},
        {"status", NonEmptyString},
        {"running", IntOrEmpty},
    };
    validate_rows(data, row_map);
  }
}

} // namespace table_tests
} // namespace osquery
