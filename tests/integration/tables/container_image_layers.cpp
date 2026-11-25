/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for container_image_layers.

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class ContainerImageLayersTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ContainerImageLayersTest, test_sanity) {
  ValidationMap row_map = {
      {"runtime", NonEmptyString},
      {"runtime_type", NonEmptyString},
      {"runtime_name", NonEmptyString},
      {"id", NormalType | EmptyOk},
      {"image_id", NormalType | EmptyOk},
      {"image", NormalType | EmptyOk},
      {"image_name", NormalType | EmptyOk},
      {"tags", NormalType | EmptyOk},
      {"layer_order", NonNegativeInt},
      {"layer_id", NonEmptyString},
      {"digest", NormalType | EmptyOk},
      {"layer_digest", NormalType | EmptyOk},
      {"diff_id", NormalType | EmptyOk},
      {"chain_id", NormalType | EmptyOk},
      {"size_bytes", IntOrEmpty},
      {"size", IntOrEmpty},
      {"media_type", NormalType | EmptyOk},
  };

  for (const auto& table_name :
       {"container_image_layers", "image_layers", "image_layer_info"}) {
    QueryData data = execute_query(std::string("select * from ") + table_name);
    if (data.empty()) {
      continue;
    }

    validate_rows(data, row_map);

    auto docker_data =
        execute_query("select id, layer_order from " + std::string(table_name) +
                      " where runtime = 'docker' order by id, layer_order");
    std::string previous_image_id;
    size_t expected_order = 1;
    for (size_t index = 0; index < docker_data.size(); ++index) {
      const auto& image_id = docker_data[index].at("id");
      if (image_id != previous_image_id) {
        previous_image_id = image_id;
        expected_order = 1;
      }
      EXPECT_EQ(docker_data[index].at("layer_order"),
                std::to_string(expected_order));
      ++expected_order;
    }
  }
}

} // namespace table_tests
} // namespace osquery
