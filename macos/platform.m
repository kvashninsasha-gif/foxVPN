#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <SystemConfiguration/SystemConfiguration.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/audit.h>
#include <stdatomic.h>

static int hashForCode(SecCodeRef code, char *out) {
 CFDictionaryRef info = NULL;
 if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) != errSecSuccess) return 0;
 NSData *hash = ((__bridge NSDictionary *)info)[(__bridge id)kSecCodeInfoUnique];
 if (hash.length != 20) { CFRelease(info); return 0; }
 const unsigned char *bytes = hash.bytes;
 for (int i=0;i<20;i++) sprintf(out+2*i,"%02x",bytes[i]);
 out[40]=0; CFRelease(info); return 1;
}
int fox_self_hash(char *out) {
 @autoreleasepool { SecCodeRef code=NULL;
 if (SecCodeCopySelf(kSecCSDefaultFlags,&code)!=errSecSuccess) return 0;
 int result=hashForCode(code,out); CFRelease(code); return result; }
}
int fox_verify_socket(int fd, const char *expected) {
 @autoreleasepool {
 audit_token_t token; socklen_t size=sizeof(token);
 if (getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&size) || size!=sizeof(token)) return 0;
 NSData *data=[NSData dataWithBytes:&token length:size];
 NSDictionary *attributes=@{(__bridge id)kSecGuestAttributeAudit:data};
 SecCodeRef code=NULL;
 if (SecCodeCopyGuestWithAttributes(NULL,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code)!=errSecSuccess) return 0;
 char actual[41];
 int ok=SecCodeCheckValidity(code,kSecCSStrictValidate,NULL)==errSecSuccess && hashForCode(code,actual) && strcmp(actual,expected)==0;
 CFRelease(code); return ok; }
}
static SCDynamicStoreRef dnsStore=NULL;
int fox_dns(int enabled) {
 @autoreleasepool {
 if (!dnsStore) dnsStore=SCDynamicStoreCreate(NULL,CFSTR("foxVPN DNS"),NULL,NULL);
 if (!dnsStore) return 0;
 CFStringRef key=CFSTR("State:/Network/Service/foxVPN/DNS");
 if (!enabled) { SCDynamicStoreRemoveValue(dnsStore,key); return 1; }
 NSDictionary *dns=@{@"ServerAddresses":@[@"172.29.0.2",@"fdfe:dcba:9876::2"],@"SupplementalMatchDomains":@[@""],@"SupplementalMatchOrders":@[@1]};
 return SCDynamicStoreSetValue(dnsStore,key,(__bridge CFDictionaryRef)dns); }
}
static _Atomic unsigned long long epoch=0;
static void changed(SCDynamicStoreRef store,CFArrayRef keys,void *context) { atomic_fetch_add(&epoch,1); }
unsigned long long fox_network_epoch(void) { return atomic_load(&epoch); }
void fox_watch_network(void) {
 @autoreleasepool {
 SCDynamicStoreRef store=SCDynamicStoreCreate(NULL,CFSTR("foxVPN network"),changed,NULL);
 if (!store) return;
 NSArray *keys=@[@"State:/Network/Global/IPv4",@"State:/Network/Global/IPv6"];
 SCDynamicStoreSetNotificationKeys(store,(__bridge CFArrayRef)keys,NULL);
 CFRunLoopSourceRef source=SCDynamicStoreCreateRunLoopSource(NULL,store,0);
 if(source) { CFRunLoopAddSource(CFRunLoopGetCurrent(),source,kCFRunLoopDefaultMode); CFRunLoopRun(); CFRelease(source); }
 CFRelease(store); }
}
