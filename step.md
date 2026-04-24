# 不同微信版本偏移查找步骤

## 前置准备

1. 用 IDA 以 **ARM64** 模式打开以下文件（分析时间很久，需耐心等待 `AU: idle`）：

```
/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework
```

2. 分析完成后，打开 Strings 窗口（**Shift+F12**），使用 **Ctrl+F** 过滤搜索

---

## Hook 点 1：搜索 `[perf] AppletIndexContainer::OnLoadStart`

**目的**：找到该函数的偏移，hook 使第二个参数（X1 寄存器）始终为 true

### 步骤

1. 在 Strings 窗口搜索 `AppletIndexContainer::OnLoadStart`（如果搜不到，尝试搜 `AppletIndexContainer` 或 `OnLoadStart`）
2. 双击字符串，跳转到引用位置
3. 按 **X** 查看交叉引用（Xrefs），找到引用该字符串的函数
4. 按 **F5** 反编译该函数，确认伪代码中包含类似以下内容：
   ```c
   sub_B37D6(..., "[perf] AppletIndexContainer::OnLoadStart", 441);
   ```
5. 记录该**函数的起始地址**（如 `sub_4EAF204`），这就是偏移值

### 在 hook.js 中的对应位置

```javascript
// 搜索[perf] AppletIndexContainer::OnLoadStart
Interceptor.attach(moduleBase.add(0x这里填偏移), {
    onEnter(args) {
        // 修改 X1 寄存器为 true
        this.context.x1 = (this.context.x1 & ~0xFF) | 0x1;
    },
    onLeave(retval) {}
});
```

---

## Hook 点 2：上个函数的最后调用的函数

**目的**：在该函数中修改某个值为 1101，使调试通道打开

### 步骤

1. 在 Hook 点 1 找到的函数中（反编译视图），找到该函数的**最后一个 return 语句**
2. 在 return 语句前，找到最后调用的子函数（如 `sub_7D80A10` 或 `sub_81CEC08`）
3. 双击进入该子函数，按 **F5** 反编译
4. 在伪代码中找到类似以下判断：
   ```c
   if (*(QWORD *)(*(QWORD *)(v4 + 1376) + 16LL) + 488LL) == 1101
   ```
5. 记录该**函数的起始地址**，这就是偏移值
6. 同时注意伪代码中的数值（如 `1376`），不同版本这个值可能不同：
   - 4.1.0.240 版本：`1336`
   - 更新版本：`1376`
   - 你需要根据实际反编译结果修改 hook.js 中 `v4.add(xxxx)` 的值

### 在 hook.js 中的对应位置

```javascript
// 搜索[perf] AppletIndexContainer::OnLoadStart，最后一个的函数
Interceptor.attach(moduleBase.add(0x这里填偏移), {
    onEnter(args) {
        try {
            const result = args[0];
            const v4 = result.add(8).readPointer();
            if (v4 && !v4.isNull()) {
                // 注意：这里的数值（1376/1336）不同版本可能不同，需根据 IDA 反编译确认
                const qword1 = v4.add(这里填IDA中的值).readPointer();
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
            console.error("Error:", error);
        }
    },
    onLeave(retval) {}
});
```

---

## Hook 点 3：搜索 `SendToClientFilter`

**目的**：使 `v8[2] != 6` 的判断为 true，绕过消息过滤

### 步骤

1. 在 Strings 窗口搜索 `SendToClientFilter`
2. 双击字符串，跳转到引用位置
3. 按 **X** 查看交叉引用，找到引用该字符串的函数
4. 按 **F5** 反编译，在伪代码中找到类似以下内容：
   ```c
   if ( v8[2] != 6 )
   ```
   以及附近有 `"SendToClientFilter"` 字符串引用
5. 记录包含此判断的**函数的起始地址**（如 `sub_7D71940`），这就是偏移值

### 在 hook.js 中的对应位置

```javascript
// 搜索 SendToClientFilter
Interceptor.attach(moduleBase.add(0x这里填偏移), {
    onEnter(args) {},
    onLeave(retval) {
        if (retval && !retval.isNull()) {
            const v8_2_address = retval.add(8);
            if (v8_2_address.readU32() == 6) {
                v8_2_address.writeU32(0x0); // 使 v8[2] != 6 为 true
            }
        }
    }
});
```

---

## Hook 点 4：搜索 `WAPCAdapterAppIndex.js`

**目的**：使该函数直接返回 0x0

### 步骤

1. 在 Strings 窗口搜索 `WAPCAdapterAppIndex.js`
2. 双击字符串，跳转到引用位置
3. 按 **X** 查看交叉引用，找到**第一个引用**的函数
4. 按 **F5** 反编译，确认函数中包含对 `WAPCAdapterAppIndex.js`、`WAServiceMainContext.js`、`WASubContext.js`、`WAWebview.js` 等字符串的引用
5. 记录该**函数的起始地址**（如 `sub_4F0555C`），这就是偏移值

### 在 hook.js 中的对应位置

```javascript
// 搜索 WAPCAdapterAppIndex.js，第一个引用
Interceptor.attach(moduleBase.add(0x这里填偏移), {
    onEnter(args) {},
    onLeave(retval) {
        retval.replace(0x0); // 直接返回 0
    }
});
```

---

## 已知版本偏移对照表

| Hook 点 | 4.1.0.240 | hook.js（未知版本） |
|---------|-----------|-----------------|
| AppletIndexContainer::OnLoadStart 函数 | `0x4EAF204` | `0x4F0620C` |
| 上个函数最后调用的函数 | `0x7D80A10`（v4+1336） | `0x81CEC08`（v4+1376） |
| SendToClientFilter | `0x7D71940` | `0x81BFC04` |
| WAPCAdapterAppIndex.js | `0x4F0555C` | `0x4F699E8` |

---

## 更新 hook.js

找到 4 个偏移后，复制 `frida/hook.js` 或 `frida/4.1.0.240.js`，修改其中的偏移值，然后启动服务：

```bash
npx ts-node src/index.ts --script frida/你的脚本.js
```
