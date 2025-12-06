#include <array>
#include <atomic>
#include <cassert>
#include <iostream>
#include <latch>
#include <memory>
#include <string_view>

#include <zeek-websocket.h>

// RAII wrapper around zws types.
template <typename T, void (*free_t)(T *)>
struct RAII : std::unique_ptr<T, decltype(free_t)> {
  RAII(T *value) : std::unique_ptr<T, decltype(free_t)>(value, free_t) {}
};

using List = RAII<zws_List, zws_list_free>;
using Client = RAII<zws_Client, zws_client_free>;
using Event = RAII<zws_Event, zws_event_free>;

static std::atomic_bool has_error = false;
static std::latch should_terminate{1};

static void received(const char *topic, const zws_Event *event) {
  const auto event_name =
      std::string_view{reinterpret_cast<const char *>(zws_event_name(event))};

  std::cerr << "Received event " << event_name << " on topic " << topic << '\n';

  if (event_name == "pong") {
    const List args = zws_event_args(event);

    assert(zws_list_size(args.get()) == 1);

    const auto *arg = zws_list_entry(args.get(), 0);
    assert(zws_value_type(arg) == ZWS_VALUE_TYPE_STRING);

    const char *msg = nullptr;
    auto len = zws_value_as_string(arg, &msg);
    assert(msg);
    std::cerr << "The server says: " << msg << '\n';

    should_terminate.count_down();
  }
}

static void error(zws_ClientError code, const char *context) {
  std::cerr << "Error: " << context << '\n';
  has_error = true;
  should_terminate.count_down();
}

int main() {
  const auto *app_name = "foo";
  const auto topics = std::array{"/ping"};
  const auto *uri = "ws://localhost:8080/v1/messages/json";

  const Client client = zws_client_new(app_name, uri, topics.data(),
                                       topics.size(), received, error, nullptr);

  if (has_error)
    return 1;

  std::string_view msg = "hi!";
  auto args_ = std::array{zws_value_new_string(msg.data(), msg.size())};
  List args = zws_list_new(args_.data(), args_.size());

  Event event = zws_event_new("ping", args.release(), nullptr);
  zws_client_publish(client.get(), "/ping", event.release());

  should_terminate.wait();

  return has_error;
}
