// GROAuth2SessionManager.m
//
// Copyright (c) 2013 Gabriel Rinaldi (http://gabrielrinaldi.me)
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

#import "GROAuth2SessionManager.h"

NSString *const kGROAuthCodeGrantType = @"authorization_code";
NSString *const kGROAuthClientCredentialsGrantType = @"client_credentials";
NSString *const kGROAuthPasswordCredentialsGrantType = @"password";
NSString *const kGROAuthRefreshGrantType = @"refresh_token";
NSString *const kGROAuthErrorFailingOperationKey = @"GROAuthErrorFailingOperation";

#pragma mark GROAuth2SessionManager (Private)

@interface GROAuth2SessionManager ()

@property(readwrite, nonatomic) NSString *serviceProviderIdentifier;
@property(readwrite, nonatomic) NSString *clientID;
@property(readwrite, nonatomic) NSString *secret;
@property(readwrite, nonatomic) NSURL *oAuthURL;

@end

#pragma mark - GROAuth2SessionManager

@implementation GROAuth2SessionManager

#pragma mark - Initializers

+ (instancetype)managerWithBaseURL:(NSURL *)url clientID:(NSString *)clientID secret:(NSString *)secret {
  return [self managerWithBaseURL:url oAuthURL:nil clientID:clientID secret:secret];
}

+ (instancetype)managerWithBaseURL:(NSURL *)url oAuthURL:(NSURL *)oAuthURL clientID:(NSString *)clientID secret:(NSString *)secret {
  return [[self alloc] initWithBaseURL:url oAuthURL:oAuthURL clientID:clientID secret:secret];
}

- (id)initWithBaseURL:(NSURL *)url clientID:(NSString *)clientID secret:(NSString *)secret {
  return [self initWithBaseURL:url oAuthURL:nil clientID:clientID secret:secret];
}

- (id)initWithBaseURL:(NSURL *)url oAuthURL:(NSURL *)oAuthURL clientID:(NSString *)clientID secret:(NSString *)secret {
  NSParameterAssert(clientID);

  self = [super initWithBaseURL:url];
  if (self) {
    [self setServiceProviderIdentifier:[[self baseURL] host]];
    [self setClientID:clientID];
    [self setSecret:secret];
    [self setOAuthURL:oAuthURL];
  }

  return self;
}

#pragma mark - Authorization headers

- (void)setAuthorizationHeaderWithToken:(NSString *)token {
  // Use the "Bearer" type as an arbitrary default
  [self setAuthorizationHeaderWithToken:token ofType:@"Bearer"];
}

- (void)setAuthorizationHeaderWithCredential:(AFOAuthCredential *)credential {
  [self setAuthorizationHeaderWithToken:[credential accessToken] ofType:[credential tokenType]];
}

- (void)setAuthorizationHeaderWithToken:(NSString *)token ofType:(NSString *)type {
  // See http://tools.ietf.org/html/rfc6749#section-7.1
  if ([[type lowercaseString] isEqualToString:@"bearer"]) {
    [[self requestSerializer] setValue:[NSString stringWithFormat:@"Bearer %@", token] forHTTPHeaderField:@"Authorization"];
  }
}

#pragma mark - Authentication

- (void)authenticateUsingOAuthWithPath:(NSString *)path username:(NSString *)username password:(NSString *)password scope:(NSString *)scope success:(void (^)(AFOAuthCredential *))success failure:(void (^)(NSError *))failure {
  NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionary];
  mutableParameters[@"grant_type"] = kGROAuthPasswordCredentialsGrantType;
  mutableParameters[@"username"] = username;
  mutableParameters[@"password"] = password;
  mutableParameters[@"scope"] = scope;

  NSDictionary *parameters = [NSDictionary dictionaryWithDictionary:mutableParameters];

  [self authenticateUsingOAuthWithPath:path parameters:parameters success:success failure:failure];
}

- (void)authenticateUsingOAuthWithPath:(NSString *)path scope:(NSString *)scope success:(void (^)(AFOAuthCredential *))success failure:(void (^)(NSError *))failure {
  NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionary];
  mutableParameters[@"grant_type"] = kGROAuthClientCredentialsGrantType;
  mutableParameters[@"scope"] = scope;

  NSDictionary *parameters = [NSDictionary dictionaryWithDictionary:mutableParameters];

  [self authenticateUsingOAuthWithPath:path parameters:parameters success:success failure:failure];
}

- (void)authenticateUsingOAuthWithPath:(NSString *)path refreshToken:(NSString *)refreshToken success:(void (^)(AFOAuthCredential *))success failure:(void (^)(NSError *))failure {
  NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionary];
  mutableParameters[@"grant_type"] = kGROAuthRefreshGrantType;
  mutableParameters[@"refresh_token"] = refreshToken;

  NSDictionary *parameters = [NSDictionary dictionaryWithDictionary:mutableParameters];

  [self authenticateUsingOAuthWithPath:path parameters:parameters success:success failure:failure];
}

- (void)authenticateUsingOAuthWithPath:(NSString *)path code:(NSString *)code redirectURI:(NSString *)redirectURI success:(void (^)(AFOAuthCredential *))success failure:(void (^)(NSError *))failure {
  NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionary];
  mutableParameters[@"grant_type"] = kGROAuthCodeGrantType;
  mutableParameters[@"code"] = code;
  mutableParameters[@"redirect_uri"] = redirectURI;

  NSDictionary *parameters = [NSDictionary dictionaryWithDictionary:mutableParameters];

  [self authenticateUsingOAuthWithPath:path parameters:parameters success:success failure:failure];
}

- (void)authenticateUsingOAuthWithPath:(NSString *)path parameters:(NSDictionary *)parameters success:(void (^)(AFOAuthCredential *))success failure:(void (^)(NSError *))failure {
  NSMutableDictionary *mutableParameters = [NSMutableDictionary dictionaryWithDictionary:parameters];
  mutableParameters[@"client_id"] = [self clientID];

  parameters = [NSDictionary dictionaryWithDictionary:mutableParameters];

  NSString *urlString;
  if ([self oAuthURL]) {
    urlString = [[NSURL URLWithString:path relativeToURL:[self oAuthURL]] absoluteString];
  }
  else {
    urlString = [[NSURL URLWithString:path relativeToURL:[self baseURL]] absoluteString];
  }

  NSError *error;
  NSMutableURLRequest *mutableRequest = [[AFHTTPRequestSerializer serializer] requestWithMethod:@"POST"
                                                                                      URLString:urlString
                                                                                     parameters:parameters
                                                                                          error:&error];
  if (error) {
    failure(error);
    return;
  }
  [mutableRequest setValue:@"Digest" forHTTPHeaderField:@"Authorization"];

  __weak typeof(self) weakSelf = self;
  NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
  AFURLSessionManager *manager = [[AFURLSessionManager alloc] initWithSessionConfiguration:configuration];
  [manager setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential **credential) {
    // TODO can check challenge count
    NSURLCredential *urlCredential = [NSURLCredential credentialWithUser:weakSelf.clientID password:weakSelf.secret
                                                             persistence:NSURLCredentialPersistenceForSession];
    [challenge.sender useCredential:urlCredential forAuthenticationChallenge:challenge];
    *credential = urlCredential;
    return NSURLSessionAuthChallengeUseCredential;
  }];

  NSURLSessionDataTask *task = [manager dataTaskWithRequest:mutableRequest completionHandler:^(NSURLResponse *response, NSDictionary *responseObject, NSError *error) {
    if (failure) {
      if (error) {
        NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithDictionary:error.userInfo];
        error = [NSError errorWithDomain:error.domain code:error.code userInfo:userInfo];
      }
      failure(error);
    }

    if (responseObject[@"error"]) {
      if (failure) {
        // TODO: Resolve the `error` field into a proper NSError object
        // http://tools.ietf.org/html/rfc6749#section-5.2
        failure(nil);
      }
      return;
    }

    NSString *refreshToken = responseObject[@"refresh_token"];
    if (refreshToken == nil || [refreshToken isEqual:[NSNull null]]) {
      refreshToken = parameters[@"refresh_token"];
    }

    AFOAuthCredential *credential = [AFOAuthCredential credentialWithOAuthToken:responseObject[@"access_token"]
                                                                      tokenType:responseObject[@"token_type"]];

    NSDate *expireDate = [NSDate distantFuture];
    id expiresIn = responseObject[@"expires_in"];
    if (expiresIn != nil && ![expiresIn isEqual:[NSNull null]]) {
      expireDate = [NSDate dateWithTimeIntervalSinceNow:[expiresIn doubleValue]];
    }

    [credential setRefreshToken:refreshToken expiration:expireDate];

    [self setAuthorizationHeaderWithCredential:credential];

    if (success) {
      success(credential);
    }


  }];
  [task resume];
}

@end
