## 用途

这是项目自建的最小 M2 reachability case，用于验证 Blueprint handler 在被
`app.register_blueprint(..., url_prefix=...)` 挂载后，系统可以从本地源码中恢复真实入口路径，
并输出 `reachable=true`。

## 关注点

- route handler 位于 `app/routes.py`
- 实际入口路径来自 `@bp.get("/login")` 与 `app.register_blueprint(..., url_prefix="/auth")`
  的组合
- sink 位于 Blueprint handler 本体内

## 失败模式

- 如果 Blueprint decorator 被直接当成已注册 app route，这个 case 可能错误丢失 `/auth`
  前缀。
- 如果 `register_blueprint` 没有和导入的 `bp` 绑定，这个 case 会错误退回
  `reachable=null`。

## 后续边界

后续可以扩展 `Blueprint.add_url_rule(...)`、`@bp.route(...)`、module alias blueprint import
或多个 `register_blueprint(...)` 变体；当前 case 只锁定最小的 direct import +
`url_prefix` 组合。
