#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zeek-websocket.h>

static atomic_bool has_error = false;
static pthread_mutex_t has_error_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t should_terminate = PTHREAD_COND_INITIALIZER;

static void received(const char *topic, const struct zws_Event *event) {
  const uint8_t *event_name = zws_event_name(event);

  printf("Received event %s on topic %s\n", zws_event_name(event), topic);

  if (strcmp((const char *)event_name, "pong") == 0) {
    struct zws_List *args = zws_event_args(event);

    assert(zws_list_size(args) == 1);

    const struct zws_Value *arg = zws_list_entry(args, 0);
    assert(zws_value_type(arg) == ZWS_VALUE_TYPE_STRING);

    const char *msg = NULL;
    uintptr_t len = zws_value_as_string(arg, &msg);
    assert(msg);
    printf("The server says: %s\n", msg);

    zws_list_free(args);

    // Finish after receiving a "pong".
    pthread_cond_signal(&should_terminate);
  }
}

static void error(enum zws_ClientError code, const char *context) {
  printf("Error: %s\n", context);
  has_error = true;
  pthread_cond_signal(&should_terminate);
}

int main(void) {
  const char *app_name = "foo";

#define NUM_TOPICS 1
  const char *topics[NUM_TOPICS] = {"/ping"};

  const char *uri = "ws://localhost:8080/v1/messages/json";

  struct zws_Client *client =
      zws_client_new(app_name, uri, topics, NUM_TOPICS, received, error, NULL);

#define NUM_ARGS 1
  const char *msg = "hi!";
  struct zws_Value *args_[NUM_ARGS] = {zws_value_new_string(msg, strlen(msg))};
  struct zws_List *args = zws_list_new(args_, NUM_ARGS);

  struct zws_Event *event = zws_event_new("ping", args, NULL);

  zws_client_publish(client, "/ping", event);

  pthread_cond_wait(&should_terminate, &has_error_mtx);

  zws_client_free(client);

  return has_error;
}
