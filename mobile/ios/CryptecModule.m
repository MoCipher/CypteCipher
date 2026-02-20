#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Cryptec, NSObject)

RCT_EXTERN_METHOD(generate_mnemonic:(NSInteger)strength resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(first_receive_address:(NSString*)mnemonic resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(create_psbt:(NSString*)mnemonic to:(NSString*)to sats:(nonnull NSNumber*)sats resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(sign_psbt:(NSString*)mnemonic psbt:(NSString*)psbt resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end
