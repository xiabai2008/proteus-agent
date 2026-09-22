/**
 * dsh-proteus-bridge —— host 平面 bundle 的入口（薄再导出）。
 *
 * **实现只有一份**：`../.agent-presets/proteus/proteus-tools-policy.mjs`
 * （随 preset 安装、供 preset 作用域内的裁决行加载）。这里只做再导出，
 * 让 host 平面的审计行复用同一份代码——两条挂载点、一份实现，不漂移。
 *
 * 为什么不在本目录实现（2026-09-22 真机实测得到的两条规则）：
 * 1. **裁决必须挂在 preset 作用域**：`tools/pre-execute` 是作用域过滤派发的，
 *    host 平面监听收不到 preset 作用域内的工具调用（web 会话里 `pwsh curl`
 *    直接执行、无审批；同一份代码在无 preset 的 headless 里能拦）。
 * 2. **preset 行解析不到包名**：DSH 对 preset 行只解析"本目录相对文件"或已装进
 *    profile 的包；写包名会得到 `broken=… cannot be resolved`，而 broken 的
 *    preset 不进选择器（界面上零提示）。反过来 bundle 行可按包名加载，且因为
 *    bundle 以 `link:` 指向本仓库，它可以相对导入 preset 目录里的那份实现。
 *
 * `role` 分工见实现文件的文件头：bundle 行用 `role: audit`
 * （`session/event` 是全局事件，host 平面可见），preset 行用 `role: policy`。
 */

export { apply, inject, name } from '../.agent-presets/proteus/proteus-tools-policy.mjs'
