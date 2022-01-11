#include "keytar.h"

// This is needed to make the builds on Ubuntu 14.04 / libsecret v0.16 work.
// The API we use has already stabilized.
#define SECRET_API_SUBJECT_TO_CHANGE
#include <libsecret/secret.h>
#include <stdio.h>
#include <string.h>

namespace keytar {

namespace {

static const SecretSchema schema = {
  "org.freedesktop.Secret.Generic", SECRET_SCHEMA_NONE, {
    { "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
    { "account", SECRET_SCHEMA_ATTRIBUTE_STRING }
  }
};

}  // namespace

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* errStr) {
  GError* error = NULL;

  secret_password_store_sync(
    &schema,                            // The schema.
    SECRET_COLLECTION_DEFAULT,          // Default collection.
    (service + "/" + account).c_str(),  // The label.
    password.c_str(),                   // The password.
    NULL,                               // Cancellable. (unneeded)
    &error,                             // Reference to the error.
    "service", service.c_str(),
    "account", account.c_str(),
    NULL);                              // End of arguments.

  if (error != NULL) {
    *errStr = std::string(error->message);
    g_error_free(error);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* errStr) {
  GError* error = NULL;

  GHashTable* search_attrs = g_hash_table_new(g_str_hash, g_str_equal);
  g_hash_table_insert(search_attrs, (void*)"account", (void*)account.c_str());
  g_hash_table_insert(search_attrs, (void*)"service", (void*)service.c_str());

  // search all items for matching secrets, prompting to unlock any locked items before returning.
  // any items that are found are also loaded right away so secret_item_get_secret can return something.
  SecretSearchFlags flags = (SecretSearchFlags)(SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK | SECRET_SEARCH_LOAD_SECRETS);
  GList* items = secret_service_search_sync(
    NULL,           // secret service instance. will be filled with default instance.
    &schema,        // the schema of the attrs of the item
    search_attrs,   // the values of the attrs
    flags,          // SecretSearchFlags
    NULL,           // Cancellation object (only works for cancelling this call, not for signaling user cancellation)
    &error          // place for errors to be reported
  );

  // something went wrong
  if (error != NULL) {
    *errStr = std::string(error->message);
    g_error_free(error);
    return FAIL_ERROR;
  }

  // there were no matching secrets
  if(!g_list_length(items)) {
    return FAIL_NONFATAL;
  }

  SecretItem* item = (SecretItem*) g_list_first(items)->data;

  // user should have unlocked the item, but didn't.
  // treated as deliberate cancellation
  if(secret_item_get_locked(item)) {
    // stringly typed errors :(
    *errStr = std::string("user_cancellation");
    return FAIL_ERROR;
  }

  SecretValue* val = secret_item_get_secret(item);

  // if val is locked or not loaded (both should be impossible)
  if(val == NULL) {
    return FAIL_NONFATAL;
  }

  // just a pointer to the secret value's internal data
  const gchar* raw_password = secret_value_get_text(val);

  // may happen if the password type is not text/plain
  // passwords set by us are always text/plain, but it
  // might have been overwritten by someone else.
  // treated as if the password was not set
  if (raw_password == NULL) {
    return FAIL_NONFATAL;
  }

  // std::string assignment overload will do the work of converting c string to std::string (copying)
  *password = raw_password;
  secret_value_unref(val);
  g_hash_table_unref(search_attrs);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* errStr) {
  GError* error = NULL;

  gboolean result = secret_password_clear_sync(
    &schema,                            // The schema.
    NULL,                               // Cancellable. (unneeded)
    &error,                             // Reference to the error.
    "service", service.c_str(),
    "account", account.c_str(),
    NULL);                              // End of arguments.

  if (error != NULL) {
    *errStr = std::string(error->message);
    g_error_free(error);
    return FAIL_ERROR;
  }

  if (!result)
    return FAIL_NONFATAL;

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* errStr) {
  GError* error = NULL;

  gchar* raw_password = secret_password_lookup_sync(
    &schema,                            // The schema.
    NULL,                               // Cancellable. (unneeded)
    &error,                             // Reference to the error.
    "service", service.c_str(),
    NULL);                              // End of arguments.

  if (error != NULL) {
    *errStr = std::string(error->message);
    g_error_free(error);
    return FAIL_ERROR;
  }

  if (raw_password == NULL)
    return FAIL_NONFATAL;

  *password = raw_password;
  secret_password_free(raw_password);
  return SUCCESS;
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* errStr) {
  GError* error = NULL;

  GHashTable* attributes = g_hash_table_new(NULL, NULL);
  g_hash_table_replace(attributes,
                       (gpointer) "service",
                       (gpointer) service.c_str());

  GList* items = secret_service_search_sync(
    NULL,
    &schema,                            // The schema.
    attributes,
    static_cast<SecretSearchFlags>(SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK |
                                   SECRET_SEARCH_LOAD_SECRETS),
    NULL,                               // Cancellable. (unneeded)
    &error);                             // Reference to the error.

  g_hash_table_destroy(attributes);

  if (error != NULL) {
    *errStr = std::string(error->message);
    g_error_free(error);
    return FAIL_ERROR;
  }

  GList* current = items;
  for (current = items; current != NULL; current = current->next) {
    SecretItem* item = reinterpret_cast<SecretItem*>(current->data);

    GHashTable* itemAttrs = secret_item_get_attributes(item);
    char* account = strdup(
      reinterpret_cast<char*>(g_hash_table_lookup(itemAttrs, "account")));

    SecretValue* secret = secret_item_get_secret(item);
    char* password = strdup(secret_value_get_text(secret));

    if (account == NULL || password == NULL) {
      if (account)
        free(account);

      if (password)
        free(password);

      continue;
    }

    credentials->push_back(Credentials(account, password));
    free(account);
    free(password);
  }

  return SUCCESS;
}

}  // namespace keytar
