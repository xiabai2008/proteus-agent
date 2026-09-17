/**
 * proteus-persona — 随 `proteus` preset 的本地插件。
 *
 * 职责只有一个：在挂载时读取 Proteus 仓库里的人格提示词文件，把它注册成
 * `deployment:persona-prefix` 分区，从而为本 preset 的会话遮蔽部署默认人格。
 *
 * 为什么用本地插件而不是 `@deepseek-ai/dsh-persona` 的 `prefix` 字段：
 * persona 的 `prefix` 是字符串字面量，而要求是"引用 prompts/ 下的文件"——
 * 提示词以仓库文件为唯一来源，不在 composition 里复制一份（复制必然漂移）。
 * preset 目录内的相对行（`name: './proteus-persona.mjs'`）由
 * `dsh-agent-presets` 的发现机制按 preset 目录解析，是本部署的既有做法。
 *
 * 依赖约束：只 import node 内置模块。preset 目录不在 harness 的 node_modules
 * 解析路径上，import harness 包会失败；分区名与 API 形状按
 * `@deepseek-ai/dsh-persona@0.1.5-rc.2` 的实装对齐（见其 lib/index.js）。
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/** Cordis 插件名（loader 诊断用）。 */
export const name = 'proteus-persona'

/** 本行贡献的提示词注册表。 */
export const inject = ['systemPrompt']

/** 分区名与 `@deepseek-ai/dsh-system-prompt` 的常量字面值一致。 */
const PERSONA_PREFIX_SECTION = 'deployment:persona-prefix'
const PERSONA_SUFFIX_SECTION = 'deployment:persona-suffix'

/**
 * 解析人格文件路径：显式配置优先，其次 `PROTEUS_HOME`，最后当前工作目录。
 * @param {object} config - 行配置。
 * @returns {string} 人格文件的绝对路径。
 */
function resolvePromptPath(config) {
  if (typeof config.promptPath === 'string' && config.promptPath !== '') {
    return config.promptPath
  }
  const home = process.env.PROTEUS_HOME ?? process.cwd()
  return resolve(home, 'prompts', 'dsh-persona.md')
}

/**
 * 读取人格文件并注册前缀（可选后缀）分区。
 * 文件读不到时抛错——挂载失败好过带着空人格静默跑起来。
 * @param {object} ctx - 挂载上下文（agent 作用域）。
 * @param {object} config - 行配置：promptPath / suffix。
 */
export function apply(ctx, config = {}) {
  const promptPath = resolvePromptPath(config)
  let text
  try {
    text = readFileSync(promptPath, 'utf8')
  } catch (error) {
    throw new Error(
      `proteus-persona: 读不到人格提示词 ${promptPath}（${error.message}）`,
    )
  }

  // 分区顺序沿用部署默认的 persona 位置；取不到就交给注册表排（不同版本
  // 的 getSectionOrder 键名可能有别，这里不因为排序拿不到就挂载失败）。
  let order
  try {
    order = ctx.systemPrompt.getSectionOrder('DEPLOYMENT_PERSONA_PREFIX')
  } catch {
    order = undefined
  }

  ctx.effect(
    () =>
      ctx.systemPrompt.section({
        name: PERSONA_PREFIX_SECTION,
        ...(order === undefined ? {} : { order }),
        text,
      }),
    'proteus-persona.section()',
  )

  const suffix = typeof config.suffix === 'string' ? config.suffix : ''
  if (suffix !== '') {
    ctx.effect(
      () =>
        ctx.systemPrompt.section({
          name: PERSONA_SUFFIX_SECTION,
          text: suffix,
        }),
      'proteus-persona.suffix()',
    )
  }
}