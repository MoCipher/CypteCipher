// UniFFI placeholder header (iOS) - generated bindings will provide concrete implementations
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Cryptec : NSObject

+ (NSString*)generate_mnemonic:(uint32_t)strength;
+ (NSString*)first_receive_address:(NSString*)mnemonic;
+ (NSString*)create_psbt:(NSString*)mnemonic to:(NSString*)to sats:(uint64_t)sats;
+ (NSString*)sign_psbt:(NSString*)mnemonic psbt:(NSString*)psbt_b64;

@end

NS_ASSUME_NONNULL_END
