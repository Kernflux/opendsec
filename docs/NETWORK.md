# 网络策略

sandbox 的网络默认拒绝一切：既不能主动连出去，也不能被别人连进来。调用方按需放行要访问的目标，管理员定义规则集和全集群的默认规则。这一页说明规则怎么写、怎么生效，以及边界情况。

前提：节点开启了 sandbox 网络（`edges[].network.enabled`，单机安装和示例配置都已开启）。没有开启的节点上，sandbox 只有回环接口，`network_rules` 被忽略。

## 1. 规则怎么写

`network_rules` 是一个字典：键是规则，值为 `true` 放行，`false` 收回。

| 规则 | 例子 | 含义 |
|---|---|---|
| 规则集名 | `pypi` | 管理员在 `network.rule_sets` 里定义的一组目标 |
| 域名 | `github.com` | 这个域名及其所有子域名（`api.github.com`、`raw.github.com` 等）。写成 `*.github.com` 效果相同 |
| IPv4 地址 | `1.2.3.4` | 这一个地址 |
| IPv4 网段 | `203.0.113.0/24`、`10.20.0.0/16` | 整个网段 |
| `*` | `*` | 所有**公网**地址（不含内网，见 §4） |

每条规则后面可以加 `:端口[/协议]`，只放行这些端口：

| 写法 | 含义 |
|---|---|
| `pypi.org:443` | 只放行 443 端口，TCP 和 UDP 都可以 |
| `10.0.0.0/8:5432/tcp` | 只放行 TCP 5432 |
| `*:443` | 所有公网地址的 443 端口 |
| `example.com:8000-8080` | 端口范围 |
| `1.1.1.1:53/udp` | 只放行 UDP 53 |

规则集里的每一项也可以带端口。

只支持 IPv4：sandbox 只有 IPv4 地址，AAAA 查询返回空结果。

### 例子

```python
# 只能装 Python 包
DSecRunArgs(..., network_rules={"pypi": True})

# 能访问公网，但只能用 HTTPS
DSecRunArgs(..., network_rules={"*:443": True})

# 访问公网，以及内网的一个数据库
DSecRunArgs(..., network_rules={"*": True, "10.20.0.15:5432/tcp": True})

# 集群默认放行公网，这个 sandbox 不要
DSecRunArgs(..., network_rules={"*": False})

# 集群默认放行公网，这个 sandbox 只允许 PyPI 的 443
DSecRunArgs(..., network_rules={"*": False, "pypi.org:443": True, "files.pythonhosted.org:443": True})
```

命令行用 `-net`，逗号分隔，`!` 表示 `false`：

```sh
opendsecctl sandbox create -backend microvm -image root/py:3.12 -net 'pypi,github.com:443'
opendsecctl sandbox create -backend microvm -image root/py:3.12 -net '!*'
```

## 2. 规则集与默认规则（管理员）

在集群配置的 `network` 段（[配置参考](CONFIGURATION.md#network)）：

```json
"network": {
  "rule_sets": {
    "pypi":   ["pypi.org", "files.pythonhosted.org"],
    "npm":    ["registry.npmjs.org"],
    "github": ["github.com", "codeload.github.com", "objects.githubusercontent.com"],
    "mirror": ["10.30.0.10:443/tcp"]
  },
  "default_rules": {"mirror": true},
  "upstream_dns": ["10.0.0.2"]
}
```

- **规则集**给常用的目标起名字，调用方写 `{"pypi": true}` 即可，不用记具体域名。规则集只在 `network_rules` 里用到时才生效。
- **默认规则**对每个 sandbox 生效，sandbox 自己的 `network_rules` 叠在上面：同一个键以 sandbox 的为准。调用方可以用 `false` 收回默认规则里的某一项。
  - 让 sandbox 默认能访问公网：`"default_rules": {"*": true}`。
  - 单机安装（quickstart）的集群没有默认规则：sandbox 默认不能访问任何地方。
  - E2B 网关创建的 sandbox 与 E2B 一致，默认放行公网，除非请求里关闭（见[从 E2B 迁移](https://kernflux.github.io/en/docs/e2b)）。
- **上游 DNS**：edge 上的 DNS 代理向这些服务器查询，默认用宿主机的 `/etc/resolv.conf`。内网有私有 DNS 时在这里指定。

## 3. 生效方式

每台 edge 用 nftables 和一个 DNS 代理执行规则：

- **出站**：sandbox 发出的每个包都进入它自己的规则链，按以下顺序判断：
  1. 放行规则里写明的地址和网段（含端口限制）；
  2. 丢弃内网、链路本地和组播地址；
  3. 放行 DNS 代理为它解析过的、属于放行域名的地址；
  4. 其余丢弃。
- **DNS**：sandbox 的 DNS 请求被重定向到 edge 的 DNS 代理。
  - 放行的域名：转发给上游解析，结果里的 IPv4 地址先加入这个 sandbox 的放行列表，再把应答交给 sandbox。所以连接总能用上刚解析到的地址。
  - 没有放行的域名：返回 NXDOMAIN（域名不存在）。
  - 放行了 `*` 时所有域名都能解析。
  - 解析学到的地址闲置 1 小时后过期，再次解析时重新加入。
- **入站**：任何主动连向 sandbox 的新连接都被丢弃，无论来自其他 sandbox、宿主机还是外部。sandbox 主动发起的连接，回包照常通过。
- **地址伪造**：sandbox 用伪造的源地址发包，匹配不到任何规则，被丢弃。
- **宿主机服务**：除 DNS 外，sandbox 连不到宿主机上的任何服务。
- **出口**：sandbox 的流量经宿主机做地址转换（masquerade）后发出，外部看到的是节点的地址。

要访问 sandbox 里运行的服务，不要走网络，用 SDK 的 `sb.http()`、API 的 `ConnectPort`，或者 E2B 网关的端口转发：这些都在 edge 上通过 sandbox 的网络命名空间访问，不经过上面的规则。

## 4. 内网地址

以下地址段只有用**地址或网段规则明确写出**时才能访问：

`0.0.0.0/8`、`10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`（含云元数据地址 `169.254.169.254`）、`172.16.0.0/12`、`192.0.0.0/24`、`192.168.0.0/16`、`198.18.0.0/15`、`224.0.0.0/4`、`240.0.0.0/4`

- `*` 不包括它们。
- 通过域名解析得到的内网地址一律拦截：即使放行了某个域名，它解析到内网地址时也连不上。这防止用 DNS 绕过规则访问内网。
- 需要访问内网的某个服务（数据库、私有镜像源、模型服务），用网段规则写明地址和端口，例如 `10.30.0.10:443/tcp`。请只放行确实需要的地址和端口：放行整段内网会让 sandbox 里运行的代码能访问到集群节点和其他内部服务。

## 5. 运行中修改

```python
await sb.update_network({"github": True})                 # 合并：在现有规则上加一条
await sb.update_network({"github": False})                # 收回
await sb.update_network({"pypi": True}, replace=True)     # 替换：只保留这一条（默认规则仍然生效）
```

```sh
opendsecctl sandbox network $ID github
opendsecctl sandbox network $ID '!github'
opendsecctl sandbox network $ID pypi -replace
```

- 需要 `sandbox.operate`。
- 放行立即生效。
- **收回立即生效，并且切断已有的连接**：连接的后续包也要经过规则链。
- 新规则写在 sandbox 的规格里，`get_sandbox` 能看到当前的规则。

## 6. 排查

| 现象 | 可能的原因 | 检查 |
|---|---|---|
| `Could not resolve host` / 域名不存在 | 域名没有放行（DNS 代理返回 NXDOMAIN） | 看 `sb.info.spec.network_rules` 和集群的 `default_rules`；注意子域名包含在内，父域名不包含 |
| 能解析但连接超时 | 端口限制不匹配；目标解析到了内网地址 | 换成不带端口的规则试一下；`getent hosts <域名>` 看解析结果 |
| 访问内网服务超时 | 内网地址需要明确的网段规则 | 加 `<地址>:<端口>/tcp` |
| 规则写法报 `invalid` | 不是合法的域名、IPv4 地址或网段；端口不在 1 到 65535；协议不是 tcp 或 udp | 看错误信息里指出的那一项 |
| 所有规则都不起作用，sandbox 只有 `lo` | 节点没有开启 sandbox 网络 | 管理员检查 `edges[].network.enabled` |
| pip 走代理或镜像源失败 | 镜像源的域名不在规则里 | 把镜像源加进规则集，或者用网段规则 |

在 sandbox 里自查：

```sh
cat /etc/resolv.conf                      # DNS 指向 sandbox 的网关
getent hosts pypi.org                     # 放行的域名能解析
python3 -c 'import urllib.request as u; print(u.urlopen("https://pypi.org/simple/", timeout=5).status)'
```
