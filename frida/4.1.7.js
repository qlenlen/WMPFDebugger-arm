const getMainModule = () => {
    return Process.findModuleByName("WeChatAppEx Framework");
}

const moduleBase = getMainModule().base;

//搜索SendToClientFilter
Interceptor.attach(moduleBase.add(0x8429414), {
    onEnter(args) {
    },
    onLeave(retval) {
        if (retval && !retval.isNull()) {
            const v8_2_address = retval.add(8);
            if (v8_2_address.readU32() == 6) {
                v8_2_address.writeU32(0x0);
            }
        }
    }
});

//搜索[perf] AppletIndexContainer::OnLoadStart，最后一个的函数
Interceptor.attach(moduleBase.add(0x8437670), {
    onEnter(args) {
        try {
            const result = args[0];
            const v4 = result.add(8).readPointer();

            if (v4 && !v4.isNull()) {
                const qword1 = v4.add(1101).readPointer();
                if (qword1 && !qword1.isNull()) {
                    const qword2 = qword1.add(16).readPointer();
                    if (qword2 && !qword2.isNull()) {
                        const targetAddress = qword2.add(488);
                        const currentValue = targetAddress.readInt();
                        const allowedValues = [1005, 1007, 1008, 1027, 1035, 1053, 1074, 1145, 1256, 1260, 1302, 1308];
                        if (allowedValues.includes(currentValue)) {
                            targetAddress.writeInt(1101);
                        }
                    }
                }
            }
        } catch (error) {
            console.error("[hook] sub_83BC8C8 error:", error);
        }
    },
    onLeave(retval) {
    }
});

// 搜索[perf] AppletIndexContainer::OnLoadStart
Interceptor.attach(moduleBase.add(0x4CDA2B0), {
    onEnter(args) {
        this.context.x1 = (this.context.x1 & ~0xFF) | 0x1;
    },
    onLeave(retval) {
    }
});

//搜索WAPCAdapterAppIndex.js，第一个引用
Interceptor.attach(moduleBase.add(0x4FD4FFC), {
    onEnter(args) {
    },
    onLeave(retval) {
        retval.replace(0x0);
    }
});
