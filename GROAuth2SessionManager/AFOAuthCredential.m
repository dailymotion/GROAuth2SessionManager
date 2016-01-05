// AFOAuthCredential.h
//
// Copyright (c) 2013 AFNetworking (http://afnetworking.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AFOAuthCredential.h"

#ifdef _SECURITY_SECITEM_H_
NSString *const kAFOAuth2CredentialServiceName = @"AFOAuthCredentialService";

static NSMutableDictionary *AFKeychainQueryDictionaryWithIdentifier(NSString *identifier, NSString *_Nullable accessGroup) {
  NSCParameterAssert(identifier);

  NSMutableDictionary *queryDictionary = [@{
          (__bridge id) kSecClass : (__bridge id) kSecClassGenericPassword,
          (__bridge id) kSecAttrService : kAFOAuth2CredentialServiceName,
          (__bridge id) kSecAttrAccount : identifier
  } mutableCopy];

  if (accessGroup) {
    queryDictionary[(__bridge id) kSecAttrAccessGroup] = accessGroup;
  }

  return queryDictionary;
}
#endif


@interface AFOAuthCredential ()
@property(readwrite, nonatomic) NSString *accessToken;
@property(readwrite, nonatomic) NSString *tokenType;
@property(readwrite, nonatomic) NSString *refreshToken;
@property(readwrite, nonatomic) NSDate *expiration;
@end

@implementation AFOAuthCredential
@synthesize accessToken = _accessToken;
@synthesize tokenType = _tokenType;
@synthesize refreshToken = _refreshToken;
@synthesize expiration = _expiration;
@dynamic expired;

#pragma mark -

+ (instancetype)credentialWithOAuthToken:(NSString *)token
                               tokenType:(NSString *)type {
  return [[self alloc] initWithOAuthToken:token tokenType:type];
}

- (id)initWithOAuthToken:(NSString *)token
               tokenType:(NSString *)type {
  self = [super init];
  if (!self) {
    return nil;
  }

  self.accessToken = token;
  self.tokenType = type;

  return self;
}

- (NSString *)description {
  NSMutableString *description = [NSMutableString stringWithFormat:@"<%@: ", NSStringFromClass([self class])];
  [description appendFormat:@"self.accessToken=%@", self.accessToken];
  [description appendFormat:@", self.tokenType=%@", self.tokenType];
  [description appendFormat:@", self.refreshToken=%@", self.refreshToken];
  [description appendFormat:@", self.expired=%d", self.expired];
  [description appendFormat:@", self.expiration=%@", self.expiration];
  [description appendString:@">"];
  return description;
}

- (void)setRefreshToken:(NSString *)refreshToken
             expiration:(NSDate *)expiration {
  if (!refreshToken || !expiration) {
    return;
  }

  self.refreshToken = refreshToken;
  self.expiration = expiration;
}

- (BOOL)isExpired {
  return [self.expiration compare:[NSDate date]] == NSOrderedAscending;
}

#pragma mark Keychain

#ifdef _SECURITY_SECITEM_H_

+ (BOOL)storeCredential:(AFOAuthCredential *)credential
         withIdentifier:(NSString *)identifier
            accessGroup:(NSString *)accessGroup {
  return [self storeCredential:credential withIdentifier:identifier useICloud:NO accessGroup:accessGroup];
}

+ (BOOL)storeCredential:(AFOAuthCredential *)credential
         withIdentifier:(NSString *)identifier
              useICloud:(BOOL)shouldUseICloud
            accessGroup:(NSString *)accessGroup {
  id securityAccessibility;
#if (defined(__IPHONE_OS_VERSION_MAX_ALLOWED) && __IPHONE_OS_VERSION_MAX_ALLOWED >= 43000) || (defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 1090)
  securityAccessibility = (__bridge id) kSecAttrAccessibleWhenUnlocked;
#endif
  return [self storeCredential:credential
                withIdentifier:identifier
             withAccessibility:securityAccessibility
                     useICloud:shouldUseICloud
                   accessGroup:accessGroup];
}

+ (BOOL)storeCredential:(AFOAuthCredential *)credential
         withIdentifier:(NSString *)identifier
      withAccessibility:(id)securityAccessibility
              useICloud:(BOOL)shouldUseICloud
            accessGroup:(NSString *)accessGroup {
  NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier, accessGroup);

  if (!credential) {
    return [self deleteCredentialWithIdentifier:identifier useICloud:shouldUseICloud accessGroup:nil];
  }

  NSMutableDictionary *updateDictionary = [NSMutableDictionary dictionary];
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:credential];
  updateDictionary[(__bridge id) kSecValueData] = data;
  if (securityAccessibility) {
    updateDictionary[(__bridge id) kSecAttrAccessible] = securityAccessibility;
  }

  if (shouldUseICloud) {
    queryDictionary[(__bridge id) kSecAttrSynchronizable] = @YES;
    updateDictionary[(__bridge id) kSecAttrSynchronizable] = @YES;
  }

  OSStatus status;
  BOOL exists = [self retrieveCredentialWithIdentifier:identifier accessGroup:accessGroup] != nil;

  if (exists) {
    status = SecItemUpdate((__bridge CFDictionaryRef) queryDictionary, (__bridge CFDictionaryRef) updateDictionary);
  }
  else {
    [queryDictionary addEntriesFromDictionary:updateDictionary];
    status = SecItemAdd((__bridge CFDictionaryRef) queryDictionary, NULL);
  }

  if (status != errSecSuccess) {
    NSLog(@"Unable to %@ credential with identifier \"%@\" (Error %li)", exists ? @"update" : @"add", identifier, (long int) status);
  }

  return (status == errSecSuccess);
}

+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup {
  return [self deleteCredentialWithIdentifier:identifier useICloud:NO accessGroup:accessGroup];
}

+ (BOOL)deleteCredentialWithIdentifier:(NSString *)identifier useICloud:(BOOL)shouldUseICloud accessGroup:(NSString *)accessGroup {
  NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier, accessGroup);

  if (shouldUseICloud) {
    queryDictionary[(__bridge id) kSecAttrSynchronizable] = @YES;
  }

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef) queryDictionary);

  if (status != errSecSuccess) {
    NSLog(@"Unable to delete credential with identifier \"%@\" (Error %li)", identifier, (long int) status);
  }

  return (status == errSecSuccess);
}

+ (AFOAuthCredential *)retrieveCredentialWithIdentifier:(NSString *)identifier accessGroup:(NSString *)accessGroup {
  return [self retrieveCredentialWithIdentifier:identifier useICloud:NO accessGroup:accessGroup];
}

+ (AFOAuthCredential *)retrieveCredentialWithIdentifier:(NSString *)identifier
                                              useICloud:(BOOL)shouldUseICloud
                                            accessGroup:(NSString *)accessGroup {
  NSMutableDictionary *queryDictionary = AFKeychainQueryDictionaryWithIdentifier(identifier, accessGroup);
  queryDictionary[(__bridge id) kSecReturnData] = (__bridge id) kCFBooleanTrue;
  queryDictionary[(__bridge id) kSecMatchLimit] = (__bridge id) kSecMatchLimitOne;

  if (shouldUseICloud) {
    queryDictionary[(__bridge id) kSecAttrSynchronizable] = @YES;
  }

  CFDataRef result = nil;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) queryDictionary, (CFTypeRef *) &result);

  if (status != errSecSuccess) {
    NSLog(@"Unable to fetch credential with identifier \"%@\" (Error %li)", identifier, (long int) status);
    return nil;
  }

  NSData *data = (__bridge_transfer NSData *) result;
  AFOAuthCredential *credential = [NSKeyedUnarchiver unarchiveObjectWithData:data];

  return credential;
}

#endif

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  self.accessToken = [decoder decodeObjectForKey:@"accessToken"];
  self.tokenType = [decoder decodeObjectForKey:@"tokenType"];
  self.refreshToken = [decoder decodeObjectForKey:@"refreshToken"];
  self.expiration = [decoder decodeObjectForKey:@"expiration"];

  return self;
}

- (void)encodeWithCoder:(NSCoder *)encoder {
  [encoder encodeObject:self.accessToken forKey:@"accessToken"];
  [encoder encodeObject:self.tokenType forKey:@"tokenType"];
  [encoder encodeObject:self.refreshToken forKey:@"refreshToken"];
  [encoder encodeObject:self.expiration forKey:@"expiration"];
}

@end
