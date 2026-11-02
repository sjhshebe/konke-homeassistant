# Konke Smart for Home Assistant

本项目是一个基于最新版本 Home Assistant 而开发的关于控客智能的集成。目的是在于把控客智能 App 中已经保存的设备能够通过 Home Assistant 进行桥接，与其他品牌的设备进行联动，从而完成部分自动化。

## 安装

### 方式一：一键安装

在 Home Assistant 的 Terminal / SSH 中运行：

```bash
curl --retry 3 --retry-all-errors --connect-timeout 15 --max-time 120 -fsSL --http1.1 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/install.sh -o /tmp/konke-install.sh && sh /tmp/konke-install.sh
```

脚本会下载最新 GitHub Release 中的 `konke.zip`，安装到 Home Assistant
的 `custom_components/konke`。安装完成后会自动重启 Home Assistant
Core。

安装指定版本时设置 `KONKE_VERSION`：

```bash
curl --retry 3 --retry-all-errors --connect-timeout 15 --max-time 120 -fsSL --http1.1 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/install.sh -o /tmp/konke-install.sh && KONKE_VERSION=v0.8.1 sh /tmp/konke-install.sh
```

如果你的环境没有 `curl`，也可以使用：

```bash
wget -q -T 30 -t 3 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/install.sh -O /tmp/konke-install.sh && sh /tmp/konke-install.sh
```

### 方式二：手动安装

1. 从 GitHub Release 下载 `konke.zip`。
2. 解压后将 `custom_components/konke` 复制到 Home Assistant 的 `/config/custom_components/konke`。
3. 重启 Home Assistant。
4. 进入 `设置 -> 设备与服务 -> 添加集成`，搜索 `控客智能` 或 `Konke Smart`。
5. 选择 `手机号和密码` 登录，填写控客账号手机号和密码；集成会自动登录控客接口，并保存后续请求需要的 token。

## 更新

### 方式一：一键更新

以后更新到最新稳定版本时，在 Home Assistant 的 Terminal / SSH 中运行：

```bash
curl --retry 3 --retry-all-errors --connect-timeout 15 --max-time 120 -fsSL --http1.1 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/update.sh -o /tmp/konke-update.sh && sh /tmp/konke-update.sh
```

更新到指定版本时设置 `KONKE_VERSION`：

```bash
curl --retry 3 --retry-all-errors --connect-timeout 15 --max-time 120 -fsSL --http1.1 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/update.sh -o /tmp/konke-update.sh && KONKE_VERSION=v0.8.1 sh /tmp/konke-update.sh
```

如果你的环境没有 `curl`，也可以使用：

```bash
wget -q -T 30 -t 3 https://raw.githubusercontent.com/sjhshebe/konke-homeassistant/main/update.sh -O /tmp/konke-update.sh && sh /tmp/konke-update.sh
```

更新脚本会复用安装脚本的逻辑，自动备份旧版本、覆盖安装最新 Release，并
重启 Home Assistant Core。

### 方式二：手动更新

1. 从 GitHub Release 下载目标版本的 `konke.zip`。
2. 用新的 `custom_components/konke` 覆盖 Home Assistant 的 `/config/custom_components/konke`。
3. 重启 Home Assistant。

## Release 与 CI

- Release 版本号使用 `vX.Y.Z`，并且必须和 `custom_components/konke/manifest.json` 中的 `version` 一致。
- 每个 Release 会上传 `konke.zip`，包内只包含 `custom_components/konke/`。
- 一键安装和一键更新默认使用最新稳定 Release；如果 Release 不存在或缺少 `konke.zip`，脚本会失败并提示原因。
- 回滚到旧版本时，运行一键更新命令并设置 `KONKE_VERSION`，例如 `KONKE_VERSION=v0.6.0`。
- GitHub Actions 会在 `main`、`dev` 的推送和 PR 上自动运行单元测试、编译检查和质量门禁；推送版本 tag 或手动触发 Release workflow 时会自动打包并发布 Release。

## 已确认接口

- API: `https://kapp.ikonke.com/api/`
- account: `https://kapp.ikonke.com/account/`
- appKey: `1592290148`
- 场景执行: `POST /api/scene/action`

控客 App 中已有场景会作为 HA 场景同步：

- `<scene_id>` - `<scene_name>`

安装后它会作为 HA 的 `scene` 实体出现，可以直接在自动化里调用 `scene.turn_on`。

## 实体

### 场景

控客普通场景会同步为 HA `scene` 实体。控客 App 内部生成的多控分组
场景，例如 `空调多控`、`新风多控`，不会从云端场景同步请求中读取，也不
会创建为 HA 实体；这些分组更像控客内部设备关系说明，日常自动化应直接
使用对应的 `climate`、`cover`、`fan` 等标准实体。

### 空调

控客空调会同步为 HA `climate` 实体。当前已实现：

- 在线/离线状态
- 当前开关状态
- 当前温度
- 目标温度
- 当前模式展示
- 当前风速展示
- `climate.turn_on`
- `climate.turn_off`
- 设置目标温度
- 设置模式：制冷、制热、送风、除湿
- 设置风速：自动、低、中、高
- 设备注册表信息：设备名、型号、建议区域、父子设备关系

### 地暖

控客地暖会同步为 HA `climate` 实体。当前已实现：

- 在线/离线状态
- 当前开关状态
- 当前温度
- 目标温度
- `climate.turn_on`
- `climate.turn_off`
- 设置目标温度
- 设置模式：自动、制热

### 窗帘

控客窗帘电机会同步为 HA `cover` 实体。当前已实现：

- 在线/离线状态
- 当前位置展示
- `cover.open_cover`
- `cover.close_cover`
- `cover.stop_cover`

### 新风

控客新风会同步为 HA `fan` 实体。当前已实现：

- 在线/离线状态
- 当前开关状态
- 当前温度展示
- 当前风速展示
- 当前模式展示
- `fan.turn_on`
- `fan.turn_off`
- 设置风速：1、2、3 档
- 设置预设模式：自动、手动
- 滤网工作时间和告警时间等状态属性

## 选项

集成选项中可以调整：

- 刷新间隔。
- 是否创建场景实体。
- 是否创建离线设备实体。
- 是否记录取证历史（默认开启）。
- 是否监听控客实时取证事件（默认开启）。
- 取证记录保留天数（默认 30 天）。
- 是否允许后台用保存的手机号/密码重新登录。

取证历史记录设备/场景下行请求、轮询状态差异、实时上报和多控配置快照。记录最多保留 20,000 条及 10 MiB，并在保存前递归脱敏凭据。关闭取证后不会新增记录，原有记录继续按保留期清理。

设备取证会读取完整分页，并把仅存在于设备缓存中的隐藏设备加入取证基线，但不会因此创建额外 HA 实体。取证关闭、HA 停机、历史截断、存储损坏或写盘失败都会形成明确覆盖断点；后续分析不会把跨断点的变化误判为连续观察结果。

HA 集成页面原有的“下载诊断”仍是按需生成当前快照，不需要单独开启。0.8.0 会在该下载中增加 `forensics` 段，包含覆盖状态、丢弃计数、最近配置快照、有界事件时间线和保守分析结果。默认禁用的诊断实体“取证状态”只显示监听、轮询、覆盖缺口及丢弃计数，不保存原始 payload，也不参与任何控制。

新增记录只能用于分析升级后的事件，不能回填升级前已经发生的设备变化。多控和定时配置只作为旁证保存；配置存在本身不代表它实际触发过。

`konke.raw_command` 已在 0.8.0 中删除。协议逆向和原始命令验证必须使用独立开发脚本，不能通过生产 HA 暴露任意设备写入口。

0.8.0 是破坏性升级。部署前应只读搜索 HA 自动化、脚本和场景配置是否引用 `konke.raw_command`；如有引用，先迁移到标准实体服务或 `konke.execute_scene`。

使用手机号和密码登录时，后台密码重新登录默认开启。这样控客 access token 或 refresh token 失效后，HA 可以自动重新登录并恢复实体，不需要手工重新认证。如果你正在用手机 App 或模拟器抓包，担心 HA 自动登录把 App 挤下线，可以在集成选项里关闭这一项。

## 更换账号 / 家庭共享

控客云对同一个账号只允许一个在线会话：新登录会让旧会话失效。因此同一个手机号不能同时登录控客 App 和 Home Assistant，谁后登录谁会把对方挤下线。

推荐的长期方案是给 Home Assistant 单独准备一个**家庭成员账号**（控客 App 里邀请家庭成员并共享设备）：

1. 在控客 App 里注册/邀请一个家庭成员账号，并确认该账号能看到家里的设备。
2. Home Assistant 中进入 `设置 -> 设备与服务 -> 控客智能`，点击集成卡片上的 **重新配置**。
3. 第一步选择登录方式（默认沿用当前方式；也可以从密码切换为 Token，反之亦然）。
4. 填写家庭成员账号的手机号和密码（或 Token），提交。
5. 集成会自动更新账号、清理旧账号的实体/设备注册表，并按新账号重新生成实体。

重新配置不会删除集成配置项，因此历史取证数据和选项设置都会保留；如果账号或家庭发生变化，实体会重新生成（实体 ID 通常按设备名保持一致）。如果只是修改同账号的密码，重新配置也会保留已有的实体和自定义设置。

如果控客 App 里删除了某些设备或场景，集成会在下一次完整的云端轮询后自动把对应的设备/实体从 HA 注册表清理掉（存在分区请求失败时不会执行清理，避免误删）。

如果你不需要 App 和 HA 同时在线，也可以保持单账号，并在集成选项中关闭“允许后台用密码重新登录”，这样 HA 不会和 App 互相抢登录态。

## 服务

也可以直接调用服务：

```yaml
service: konke.execute_scene
data:
  scene_id: <scene_id>
```

手动刷新控客云端数据：

```yaml
service: konke.refresh
```

管理员可以清除当前配置项的取证历史：

```yaml
service: konke.clear_forensic_history
data:
  entry_id: <entry_id>
```

如果 HA 里配置了多个控客账号，可以加 `entry_id` 指定配置项。

## 注意

- 这是云端接口集成，不是局域网本地协议。
- 控客 token 和密码会保存在 HA 配置存储中，请确保 HA 主机可信。
- 控客云同一账号只允许一个在线会话：HA 和控客 App 同时登录会互相挤下线。推荐给 HA 单独使用家庭成员账号（通过 `重新配置` 切换），或关闭后台密码重新登录。
- 手机号和密码登录模式会默认允许后台自动重新登录；抓包调试时如需避免和控客手机 App/模拟器抢登录态，可以在集成选项中关闭。0.8.1 起，仅因“token 即将过期”触发的主动续期不会再使用密码重新登录，避免无意义的会话抢占。
- 已抓包确认的能力优先暴露为标准 HA 实体。日常自动化建议直接调用 `climate`、`cover`、`scene` 等标准服务。
- GitHub 仓库只包含源码和脱敏测试数据，不包含你的真实 HA 运行时设备清单。HA 的“下载诊断”会从本机实例生成数据，可能包含房间名、设备名、设备 ID 等家庭结构信息；只有你手动导出并发送给别人时才会泄露这些信息。
- 取证结论采用保守措辞。未发现 HA 下行写请求不等于已经证明是控客 App、米家、云端自动化或硬件故障；最终来源仍可能需要控客官方后台日志。
