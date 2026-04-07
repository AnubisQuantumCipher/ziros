#if TARGET_OS_IOS
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZKFWalletWebViewHost : NSObject

- (void)loadHelperRootURL:(NSURL *)helperRootURL completion:(void (^)(NSError * _Nullable error))completion;
- (void)evaluateJavaScript:(NSString *)script completion:(void (^)(NSError * _Nullable error))completion;
- (void)callAsyncJavaScript:(NSString *)body
                  arguments:(NSDictionary<NSString *, id> *)arguments
                 completion:(void (^)(id _Nullable result, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
#endif
