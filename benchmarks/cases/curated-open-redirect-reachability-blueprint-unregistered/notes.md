## 用途

这是项目自建的最小 M2 reachability negative case，用于验证 Blueprint handler
如果没有被 `register_blueprint(...)` 挂载，系统必须继续保持 `reachable=null`。

## 关注点

- handler 使用 `@bp.get("/login")`
- 本地源码中不存在 `app.register_blueprint(...)`
- 候选 taint path 仍然存在，但缺少 app-level entrypoint evidence

## 失败模式

- 如果系统把所有 `@bp.get(...)` 都直接当成真实入口，这个 case 会被错误升级为
  `reachable=true`。
- 如果系统因为缺少注册证据而误判为 `reachable=false`，也会违反当前三态语义。

## 后续边界

后续如果引入更强的 app factory / blueprint registration 解析，可以继续保留该 case
作为 “未注册 Blueprint 不能算可触达” 的负例回归。
