#include <arpa/inet.h>

#include <array>
#include <cstring>
#include <string_view>

#include <gtest/gtest.h>
#include <zeek-websocket.h>

// RAII wrapper around zws types.
template <typename T, void (*free_t)(T *)>
struct RAII : std::unique_ptr<T, decltype(free_t)> {
  RAII(T *value) : std::unique_ptr<T, decltype(free_t)>(value, free_t) {}
};

using Address = RAII<zws_Address, zws_address_free>;
using List = RAII<zws_List, zws_list_free>;
using Value = RAII<zws_Value, zws_value_free>;

TEST(Address, V4) {
  struct in_addr lo;
  memset(&lo, 0, sizeof(lo));
  ASSERT_TRUE(inet_pton(AF_INET, "127.0.0.1", &lo.s_addr));

  Address addr = zws_address_new_v4(&lo);
  ASSERT_FALSE(zws_address_is_v6(addr.get()));

  in_addr result;
  memset(&result, 0, sizeof(result));
  ASSERT_TRUE(zws_address_as_v4(addr.get(), &result));
  EXPECT_EQ(std::string_view(inet_ntoa(result)), "127.0.0.1");
}

TEST(Address, V6) {
  struct in6_addr lo;
  memset(&lo, 0, sizeof(lo));
  ASSERT_TRUE(inet_pton(AF_INET6, "::1", &lo));

  Address addr = zws_address_new_v6(&lo);
  ASSERT_TRUE(zws_address_is_v6(addr.get()));

  in6_addr result;
  memset(&result, 0, sizeof(result));
  ASSERT_TRUE(zws_address_as_v6(addr.get(), &result));

  std::string buf(INET6_ADDRSTRLEN, '\0');
  ASSERT_TRUE(inet_ntop(AF_INET6, &result, buf.data(), buf.size()));
  EXPECT_EQ(std::string_view(buf.c_str()), "::1");
}

TEST(List, empty) {
  {
    List xs = zws_list_new(nullptr, 0);
    EXPECT_EQ(zws_list_size(xs.get()), 0);
  }

  {
    List xs = zws_list_new(nullptr, 1);
    EXPECT_EQ(zws_list_size(xs.get()), 0);
  }

  {
    std::array values{static_cast<zws_Value *>(nullptr)};
    List xs = zws_list_new(values.data(), 0);
    EXPECT_EQ(zws_list_size(xs.get()), 0);
  }
}
