#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

typedef CFDataRef (*SecACCopyDataFn)(SecAccessControlRef);
typedef SecAccessControlRef (*SecACCreateFromDataFn)(CFAllocatorRef, CFDataRef, CFErrorRef *);

static NSArray<NSString *> *buildPatterns(NSString *appsCsv) {
    NSMutableArray<NSString *> *pats = [NSMutableArray arrayWithArray:@[
        @"TQ62GSZBBR",
        @"858FPG75R9",
        @"MJ797D8U6F",
        @"com.zhiliaoapp.musically",
        @"com.ss.iphone.ugc.Ame",
        @"com.zhiliaoapp.shared",
        @"com.chainlogin",
        @"com.chainassociate",
        @"Bytemod",
        @"T7285ECWW9.com.ookla.speedtest"
    ]];
    if (appsCsv.length > 0) {
        NSCharacterSet *sep = [NSCharacterSet characterSetWithCharactersInString:@",; \t\r\n"];
        for (NSString *rawTok in [appsCsv componentsSeparatedByCharactersInSet:sep]) {
            NSString *tok = rawTok;
            NSRange hashRange = [tok rangeOfString:@"#"];
            if (hashRange.location != NSNotFound) {
                tok = [tok substringToIndex:hashRange.location];
            }
            if (tok.length > 0 && ![pats containsObject:tok]) {
                [pats addObject:tok];
            }
        }
    }
    return pats;
}

static BOOL itemMatchesPatterns(NSDictionary *item, NSArray<NSString *> *pats) {
    NSString *agrp = item[(__bridge id)kSecAttrAccessGroup];
    NSString *svce = item[(__bridge id)kSecAttrService];
    NSString *acct = item[(__bridge id)kSecAttrAccount];
    for (NSString *p in pats) {
        if ([agrp isKindOfClass:[NSString class]] && [agrp rangeOfString:p options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
        if ([svce isKindOfClass:[NSString class]] && [svce rangeOfString:p options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
        if ([acct isKindOfClass:[NSString class]] && [acct rangeOfString:p options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    return NO;
}

static int cmdClean(NSString *appsCsv) {
    NSArray<NSString *> *pats = buildPatterns(appsCsv);
    NSArray *classes = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate,
        (__bridge id)kSecClassIdentity
    ];

    int matched = 0;
    int secDeleted = 0;
    OSStatus lastErr = errSecSuccess;
    OSStatus genpSt = -999;
    OSStatus emptyDelSt = SecItemDelete((__bridge CFDictionaryRef)@{});

    for (id secClass in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecReturnPersistentRef: @YES,
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            (__bridge id)kSecUseAuthenticationUI: (__bridge id)kSecUseAuthenticationUISkip
        };
        CFTypeRef res = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
        if (secClass == (__bridge id)kSecClassGenericPassword) {
            genpSt = st;
        }
        if (st != errSecSuccess) {
            lastErr = st;
        }
        if (st == errSecSuccess && res) {
            NSArray *items = CFBridgingRelease(res);
            if ([items isKindOfClass:[NSArray class]]) {
                for (NSDictionary *item in items) {
                    if (![item isKindOfClass:[NSDictionary class]]) continue;
                    if (!itemMatchesPatterns(item, pats)) continue;
                    matched++;
                    NSData *pref = item[(__bridge id)kSecValuePersistentRef];
                    if (pref) {
                        NSDictionary *delQ = @{
                            (__bridge id)kSecValuePersistentRef: pref,
                            (__bridge id)kSecUseAuthenticationUI: (__bridge id)kSecUseAuthenticationUISkip
                        };
                        OSStatus dst = SecItemDelete((__bridge CFDictionaryRef)delQ);
                        if (dst == errSecSuccess) {
                            secDeleted++;
                            continue;
                        }
                    }
                    NSMutableDictionary *fbQ = [NSMutableDictionary dictionary];
                    fbQ[(__bridge id)kSecClass] = secClass;
                    if (item[(__bridge id)kSecAttrAccessGroup]) fbQ[(__bridge id)kSecAttrAccessGroup] = item[(__bridge id)kSecAttrAccessGroup];
                    if (item[(__bridge id)kSecAttrService]) fbQ[(__bridge id)kSecAttrService] = item[(__bridge id)kSecAttrService];
                    if (item[(__bridge id)kSecAttrAccount]) fbQ[(__bridge id)kSecAttrAccount] = item[(__bridge id)kSecAttrAccount];
                    fbQ[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kSecAttrSynchronizableAny;
                    fbQ[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUISkip;
                    if (SecItemDelete((__bridge CFDictionaryRef)fbQ) == errSecSuccess) {
                        secDeleted++;
                    }
                }
            }
        }
    }

    printf("{\"status\":\"success\",\"uid\":%d,\"euid\":%d,\"sec_deleted\":%d,\"matched\":%d,\"copy_err\":%d,\"genp_st\":%d,\"empty_del_st\":%d,\"sql_deleted\":0}\n",
           (int)getuid(), (int)geteuid(), secDeleted, matched, (int)lastErr, (int)genpSt, (int)emptyDelSt);
    return 0;
}

static int cmdDump(NSString *appsCsv, NSString *outPath) {
    NSArray<NSString *> *pats = buildPatterns(appsCsv);
    NSArray *classes = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword
    ];
    NSMutableArray *outItems = [NSMutableArray array];

    for (id secClass in classes) {
        NSDictionary *q = @{
            (__bridge id)kSecClass: secClass,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
            (__bridge id)kSecReturnAttributes: @YES,
            (__bridge id)kSecReturnData: @YES,
            (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny,
            (__bridge id)kSecUseAuthenticationUI: (__bridge id)kSecUseAuthenticationUISkip
        };
        CFTypeRef res = NULL;
        OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
        if (st == errSecSuccess && res) {
            NSArray *items = CFBridgingRelease(res);
            if ([items isKindOfClass:[NSArray class]]) {
                for (NSDictionary *item in items) {
                    if (![item isKindOfClass:[NSDictionary class]]) continue;
                    if (!itemMatchesPatterns(item, pats)) continue;
                    NSMutableDictionary *d = [NSMutableDictionary dictionary];
                    d[@"class"] = secClass;
                    for (NSString *k in @[@"agrp", @"svce", @"acct", @"v_Data", @"pdmn", @"sync", @"tomb", @"cdat", @"mdat", @"sha1", @"musr", @"gena", @"desc", @"icmt", @"type", @"crtr"]) {
                        id val = item[k];
                        if (val) d[k] = val;
                    }
                    id accc = item[(__bridge id)kSecAttrAccessControl];
                    if (accc) {
                        SecACCopyDataFn fnCopy = (SecACCopyDataFn)dlsym(RTLD_DEFAULT, "SecAccessControlCopyData");
                        if (fnCopy) {
                            CFDataRef acData = fnCopy((__bridge SecAccessControlRef)accc);
                            if (acData) {
                                d[@"accc"] = CFBridgingRelease(acData);
                            }
                        }
                    }
                    [outItems addObject:d];
                }
            }
        }
    }

    NSError *err = nil;
    NSData *plistData = [NSPropertyListSerialization dataWithPropertyList:outItems format:NSPropertyListBinaryFormat_v1_0 options:0 error:&err];
    if (!plistData || ![plistData writeToFile:outPath atomically:YES]) {
        printf("{\"status\":\"error\",\"message\":\"write dump failed\"}\n");
        return 1;
    }
    printf("{\"status\":\"success\",\"count\":%lu}\n", (unsigned long)outItems.count);
    return 0;
}

static int cmdRestore(NSString *inPath) {
    NSData *raw = [NSData dataWithContentsOfFile:inPath];
    if (!raw) {
        printf("{\"status\":\"error\",\"message\":\"read restore file failed\"}\n");
        return 1;
    }
    NSArray *items = [NSPropertyListSerialization propertyListWithData:raw options:NSPropertyListImmutable format:NULL error:nil];
    if (![items isKindOfClass:[NSArray class]]) {
        printf("{\"status\":\"error\",\"message\":\"invalid plist\"}\n");
        return 1;
    }
    int added = 0;
    for (NSDictionary *orig in items) {
        if (![orig isKindOfClass:[NSDictionary class]]) continue;
        NSMutableDictionary *d = [orig mutableCopy];
        NSData *acData = d[@"accc"];
        if ([acData isKindOfClass:[NSData class]]) {
            SecACCreateFromDataFn fnCreate = (SecACCreateFromDataFn)dlsym(RTLD_DEFAULT, "SecAccessControlCreateFromData");
            if (fnCreate) {
                CFErrorRef cfErr = NULL;
                SecAccessControlRef ac = fnCreate(kCFAllocatorDefault, (__bridge CFDataRef)acData, &cfErr);
                if (ac) {
                    d[(__bridge id)kSecAttrAccessControl] = CFBridgingRelease(ac);
                } else {
                    [d removeObjectForKey:@"accc"];
                }
                if (cfErr) CFRelease(cfErr);
            } else {
                [d removeObjectForKey:@"accc"];
            }
        }
        NSMutableDictionary *delQ = [NSMutableDictionary dictionary];
        if (d[@"class"]) delQ[@"class"] = d[@"class"];
        if (d[@"agrp"]) delQ[@"agrp"] = d[@"agrp"];
        if (d[@"svce"]) delQ[@"svce"] = d[@"svce"];
        if (d[@"acct"]) delQ[@"acct"] = d[@"acct"];
        delQ[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUISkip;
        SecItemDelete((__bridge CFDictionaryRef)delQ);
        if (SecItemAdd((__bridge CFDictionaryRef)d, NULL) == errSecSuccess) {
            added++;
        }
    }
    printf("{\"status\":\"success\",\"added\":%d}\n", added);
    return 0;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            printf("{\"status\":\"error\",\"message\":\"usage: DelInfoKC <clean|dump|restore> ...\"}\n");
            return 1;
        }
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];
        if ([cmd isEqualToString:@"clean"]) {
            NSString *apps = (argc >= 3) ? [NSString stringWithUTF8String:argv[2]] : @"";
            return cmdClean(apps);
        } else if ([cmd isEqualToString:@"dump"] && argc >= 4) {
            return cmdDump([NSString stringWithUTF8String:argv[2]], [NSString stringWithUTF8String:argv[3]]);
        } else if ([cmd isEqualToString:@"restore"] && argc >= 3) {
            return cmdRestore([NSString stringWithUTF8String:argv[2]]);
        }
        printf("{\"status\":\"error\",\"message\":\"unknown command\"}\n");
        return 1;
    }
}
