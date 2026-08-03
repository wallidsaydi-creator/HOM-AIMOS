#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SECRET_BYTES (1024 * 1024)

static int fail(const char *reason, OSStatus status) {
  if (status == 0) {
    fprintf(stderr, "aimos_keychain_set_failed:%s\n", reason);
  } else {
    fprintf(stderr, "aimos_keychain_set_failed:%s:%d\n", reason, (int)status);
  }
  return 1;
}

static uint8_t *read_secret(size_t *length) {
  size_t capacity = 4096;
  size_t used = 0;
  uint8_t *buffer = malloc(capacity);
  if (buffer == NULL) return NULL;

  for (;;) {
    if (used == capacity) {
      if (capacity >= MAX_SECRET_BYTES) {
        free(buffer);
        return NULL;
      }
      size_t next = capacity * 2;
      if (next > MAX_SECRET_BYTES) next = MAX_SECRET_BYTES;
      uint8_t *resized = realloc(buffer, next);
      if (resized == NULL) {
        free(buffer);
        return NULL;
      }
      buffer = resized;
      capacity = next;
    }
    ssize_t count = read(STDIN_FILENO, buffer + used, capacity - used);
    if (count < 0) {
      memset(buffer, 0, capacity);
      free(buffer);
      return NULL;
    }
    if (count == 0) break;
    used += (size_t)count;
  }

  if (used == 0) {
    free(buffer);
    return NULL;
  }
  *length = used;
  return buffer;
}

static CFDictionaryRef create_query(CFStringRef service, CFStringRef account) {
  const void *query_keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
  const void *query_values[] = { kSecClassGenericPassword, service, account };
  return CFDictionaryCreate(
    kCFAllocatorDefault,
    query_keys,
    query_values,
    3,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
}

static int get_item(CFStringRef service, CFStringRef account) {
  const void *query_keys[] = {
    kSecClass,
    kSecAttrService,
    kSecAttrAccount,
    kSecReturnData,
    kSecMatchLimit,
  };
  const void *query_values[] = {
    kSecClassGenericPassword,
    service,
    account,
    kCFBooleanTrue,
    kSecMatchLimitOne,
  };
  CFDictionaryRef query = CFDictionaryCreate(
    kCFAllocatorDefault,
    query_keys,
    query_values,
    5,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks
  );
  if (query == NULL) return fail("query_allocation", 0);
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching(query, &result);
  CFRelease(query);
  if (status == errSecItemNotFound) return 44;
  if (status != errSecSuccess || result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
    if (result != NULL) CFRelease(result);
    return fail("security_framework_get", status);
  }
  CFDataRef data = (CFDataRef)result;
  const UInt8 *bytes = CFDataGetBytePtr(data);
  CFIndex length = CFDataGetLength(data);
  CFIndex written = 0;
  while (written < length) {
    ssize_t count = write(STDOUT_FILENO, bytes + written, (size_t)(length - written));
    if (count <= 0) {
      CFRelease(result);
      return fail("stdout_write", 0);
    }
    written += count;
  }
  CFRelease(result);
  return 0;
}

static int set_item(CFStringRef service, CFStringRef account) {
  size_t secret_length = 0;
  uint8_t *secret = read_secret(&secret_length);
  if (secret == NULL) return fail("secret_read", 0);
  CFDataRef data = CFDataCreate(kCFAllocatorDefault, secret, (CFIndex)secret_length);
  memset(secret, 0, secret_length);
  free(secret);
  if (data == NULL) return fail("allocation", 0);

  CFDictionaryRef query = create_query(service, account);
  if (query == NULL) {
    CFRelease(data);
    return fail("query_allocation", 0);
  }

  CFTypeRef existing = NULL;
  OSStatus status = SecItemCopyMatching(query, &existing);
  if (existing != NULL) CFRelease(existing);
  if (status == errSecSuccess) {
    const void *update_keys[] = { kSecValueData };
    const void *update_values[] = { data };
    CFDictionaryRef update = CFDictionaryCreate(
      kCFAllocatorDefault,
      update_keys,
      update_values,
      1,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks
    );
    status = update == NULL ? errSecAllocate : SecItemUpdate(query, update);
    if (update != NULL) CFRelease(update);
  } else if (status == errSecItemNotFound) {
    const void *add_keys[] = {
      kSecClass,
      kSecAttrService,
      kSecAttrAccount,
      kSecValueData,
    };
    const void *add_values[] = {
      kSecClassGenericPassword,
      service,
      account,
      data,
    };
    CFDictionaryRef add = CFDictionaryCreate(
      kCFAllocatorDefault,
      add_keys,
      add_values,
      4,
      &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks
    );
    status = add == NULL ? errSecAllocate : SecItemAdd(add, NULL);
    if (add != NULL) CFRelease(add);
  }

  CFRelease(query);
  CFRelease(data);
  if (status != errSecSuccess) return fail("security_framework_set", status);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 4) return fail("usage", 0);
  if (strlen(argv[2]) == 0 || strlen(argv[2]) > 512
      || strlen(argv[3]) == 0 || strlen(argv[3]) > 512) {
    return fail("identifier_invalid", 0);
  }

  CFStringRef service = CFStringCreateWithCString(kCFAllocatorDefault, argv[2], kCFStringEncodingUTF8);
  CFStringRef account = CFStringCreateWithCString(kCFAllocatorDefault, argv[3], kCFStringEncodingUTF8);
  if (service == NULL || account == NULL) {
    if (service != NULL) CFRelease(service);
    if (account != NULL) CFRelease(account);
    return fail("allocation", 0);
  }
  int result;
  if (strcmp(argv[1], "get") == 0) {
    result = get_item(service, account);
  } else if (strcmp(argv[1], "set") == 0) {
    result = set_item(service, account);
  } else {
    result = fail("unknown_command", 0);
  }
  CFRelease(service);
  CFRelease(account);
  return result;
}
