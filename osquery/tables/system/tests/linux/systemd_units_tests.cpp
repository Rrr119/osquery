/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <dbus/dbus.h>

#include <gtest/gtest.h>

#include <osquery/tables/system/linux/dbus/methods/listunitsmethodhandler.h>
#include <osquery/tables/system/linux/systemd_units.h>

namespace osquery {
namespace tables {

class SystemdUnitsTests : public testing::Test {};

TEST_F(SystemdUnitsTests, get_unit_type_from_id) {
  EXPECT_EQ(getUnitType("sshd.service"), "service");
  EXPECT_EQ(getUnitType("dbus.socket"), "socket");
  EXPECT_EQ(getUnitType("apt-daily.timer"), "timer");
  EXPECT_EQ(getUnitType("sys-devices-pci.device"), "device");
  EXPECT_EQ(getUnitType("run-user-1000.mount"), "mount");
  EXPECT_EQ(getUnitType("emergency.target"), "target");
}

TEST_F(SystemdUnitsTests, get_unit_type_handles_dots_inside_name) {
  // Only the suffix after the last dot is the unit type.
  EXPECT_EQ(getUnitType("foo-bar.baz.service"), "service");
  EXPECT_EQ(getUnitType("systemd-journald-audit.socket"), "socket");
}

TEST_F(SystemdUnitsTests, get_unit_type_without_suffix) {
  EXPECT_EQ(getUnitType("plainunitname"), "");
  EXPECT_EQ(getUnitType(""), "");
  EXPECT_EQ(getUnitType("trailingdot."), "");
}

namespace {

// Builds a synthetic ListUnits reply containing the given units, mirroring
// the (ssssssouso) struct layout used by the systemd Manager API.
DBusMessage* createListUnitsReply(
    const std::vector<ListUnitsMethodHandler::Unit>& units) {
  DBusMessage* message = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
  EXPECT_NE(message, nullptr);

  DBusMessageIter root_it{};
  dbus_message_iter_init_append(message, &root_it);

  DBusMessageIter array_it{};
  dbus_message_iter_open_container(
      &root_it, DBUS_TYPE_ARRAY, "(ssssssouso)", &array_it);

  for (const auto& unit : units) {
    DBusMessageIter struct_it{};
    dbus_message_iter_open_container(
        &array_it, DBUS_TYPE_STRUCT, nullptr, &struct_it);

    const char* id = unit.id.c_str();
    const char* description = unit.description.c_str();
    const char* load_state = unit.load_state.c_str();
    const char* active_state = unit.active_state.c_str();
    const char* sub_state = unit.sub_state.c_str();
    const char* following = unit.following.c_str();
    const char* path = unit.path.c_str();
    dbus_uint32_t job_id = unit.job_id;
    const char* job_type = unit.job_type.c_str();
    const char* job_path = unit.job_path.c_str();

    dbus_message_iter_append_basic(&struct_it, DBUS_TYPE_STRING, &id);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &description);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &load_state);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &active_state);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &sub_state);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &following);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_OBJECT_PATH, &path);
    dbus_message_iter_append_basic(&struct_it, DBUS_TYPE_UINT32, &job_id);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_STRING, &job_type);
    dbus_message_iter_append_basic(
        &struct_it, DBUS_TYPE_OBJECT_PATH, &job_path);

    dbus_message_iter_close_container(&array_it, &struct_it);
  }

  dbus_message_iter_close_container(&root_it, &array_it);
  return message;
}

ListUnitsMethodHandler::Unit makeUnit(const std::string& id,
                                      const std::string& load_state,
                                      const std::string& active_state,
                                      const std::string& sub_state) {
  ListUnitsMethodHandler::Unit unit;
  unit.id = id;
  unit.description = "description of " + id;
  unit.load_state = load_state;
  unit.active_state = active_state;
  unit.sub_state = sub_state;
  unit.following = "";
  unit.path = "/org/freedesktop/systemd1/unit/test";
  unit.job_id = 0U;
  unit.job_type = "";
  unit.job_path = "/";
  return unit;
}

} // namespace

TEST_F(SystemdUnitsTests, parse_list_units_reply) {
  const std::vector<ListUnitsMethodHandler::Unit> expected_units = {
      makeUnit("sshd.service", "loaded", "active", "running"),
      makeUnit("apt-daily.timer", "loaded", "active", "waiting"),
  };

  DBusMessage* reply = createListUnitsReply(expected_units);
  ASSERT_NE(reply, nullptr);

  DBusMessageIter message_it{};
  dbus_message_iter_init(reply, &message_it);
  ASSERT_EQ(dbus_message_iter_get_arg_type(&message_it), DBUS_TYPE_ARRAY);

  DBusMessageIter array_it{};
  dbus_message_iter_recurse(&message_it, &array_it);

  ListUnitsMethodHandler::Output parsed_units;
  auto status = parseListUnitsReply(parsed_units, array_it);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  ASSERT_EQ(parsed_units.size(), expected_units.size());

  for (std::size_t index = 0U; index < expected_units.size(); ++index) {
    const auto& expected = expected_units.at(index);
    const auto& parsed = parsed_units.at(index);

    EXPECT_EQ(parsed.id, expected.id);
    EXPECT_EQ(parsed.description, expected.description);
    EXPECT_EQ(parsed.load_state, expected.load_state);
    EXPECT_EQ(parsed.active_state, expected.active_state);
    EXPECT_EQ(parsed.sub_state, expected.sub_state);
    EXPECT_EQ(parsed.following, expected.following);
    EXPECT_EQ(parsed.path, expected.path);
    EXPECT_EQ(parsed.job_id, expected.job_id);
    EXPECT_EQ(parsed.job_type, expected.job_type);
    EXPECT_EQ(parsed.job_path, expected.job_path);
  }

  dbus_message_unref(reply);
}

TEST_F(SystemdUnitsTests, parse_list_units_reply_empty) {
  DBusMessage* reply = createListUnitsReply({});
  ASSERT_NE(reply, nullptr);

  DBusMessageIter message_it{};
  dbus_message_iter_init(reply, &message_it);

  DBusMessageIter array_it{};
  dbus_message_iter_recurse(&message_it, &array_it);

  ListUnitsMethodHandler::Output parsed_units;
  auto status = parseListUnitsReply(parsed_units, array_it);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  EXPECT_TRUE(parsed_units.empty());

  dbus_message_unref(reply);
}

TEST_F(SystemdUnitsTests, parse_list_units_reply_rejects_wrong_type) {
  DBusMessage* reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
  ASSERT_NE(reply, nullptr);

  DBusMessageIter root_it{};
  dbus_message_iter_init_append(reply, &root_it);
  const char* dummy = "not an array";
  dbus_message_iter_append_basic(&root_it, DBUS_TYPE_STRING, &dummy);

  DBusMessageIter array_it{};
  dbus_message_iter_init(reply, &array_it);

  ListUnitsMethodHandler::Output parsed_units;
  auto status = parseListUnitsReply(parsed_units, array_it);
  EXPECT_FALSE(status.ok());

  dbus_message_unref(reply);
}

} // namespace tables
} // namespace osquery
