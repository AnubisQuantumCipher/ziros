#if TARGET_OS_IOS
#import "ZKFWalletWebViewHost.h"

#import <WebKit/WebKit.h>

@interface ZKFWalletWebViewHost () <WKNavigationDelegate>

@property (nonatomic, strong) WKWebView *webView;
@property (nonatomic, copy, nullable) void (^pendingLoadCompletion)(NSError * _Nullable error);
@property (nonatomic, assign) BOOL pageLoaded;

@end

@implementation ZKFWalletWebViewHost

- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
    configuration.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];
    configuration.defaultWebpagePreferences.allowsContentJavaScript = YES;

    _webView = [[WKWebView alloc] initWithFrame:CGRectZero configuration:configuration];
    _webView.hidden = YES;
    _webView.navigationDelegate = self;
    _pageLoaded = NO;
    return self;
}

- (void)loadHelperRootURL:(NSURL *)helperRootURL completion:(void (^)(NSError * _Nullable error))completion {
    if (self.pageLoaded) {
        completion(nil);
        return;
    }

    self.pendingLoadCompletion = [completion copy];
    [self.webView loadHTMLString:@"<!doctype html><html><head><meta charset=\"utf-8\"></head><body></body></html>"
                         baseURL:helperRootURL];
}

- (void)evaluateJavaScript:(NSString *)script completion:(void (^)(NSError * _Nullable error))completion {
    [self.webView evaluateJavaScript:script completionHandler:^(__unused id result, NSError *error) {
        completion(error);
    }];
}

- (void)callAsyncJavaScript:(NSString *)body
                  arguments:(NSDictionary<NSString *,id> *)arguments
                 completion:(void (^)(id _Nullable result, NSError * _Nullable error))completion {
    [self.webView callAsyncJavaScript:body
                            arguments:arguments
                              inFrame:nil
                       inContentWorld:WKContentWorld.pageWorld
                    completionHandler:^(id _Nullable result, NSError * _Nullable error) {
        completion(result, error);
    }];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    (void)webView;
    (void)navigation;
    self.pageLoaded = YES;
    if (self.pendingLoadCompletion) {
        self.pendingLoadCompletion(nil);
        self.pendingLoadCompletion = nil;
    }
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    (void)webView;
    (void)navigation;
    if (self.pendingLoadCompletion) {
        self.pendingLoadCompletion(error);
        self.pendingLoadCompletion = nil;
    }
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    (void)webView;
    (void)navigation;
    if (self.pendingLoadCompletion) {
        self.pendingLoadCompletion(error);
        self.pendingLoadCompletion = nil;
    }
}

@end
#endif
