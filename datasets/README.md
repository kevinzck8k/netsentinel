# Datasets for Telco Multi-Agent AIOps Platform

本目录存放**公开可下载**的网络/日志数据集，并加工成平台可用的评测集与 RAG 历史案例。

> 这些数据主要用于 **RAG 知识增强** 与 **评测 (golden cases)**，不是用来训练大模型的。

## 已下载来源（免费 / 研究用途）

| 数据集 | 来源 | 大小约 | 用途 |
|--------|------|--------|------|
| **SFU BGP RIPE CSV** | [SFU CNL](https://www.sfu.ca/~ljilja/cnl/projects/BGP_datasets/index.html) | ~1.3 MB | 历史 BGP 异常（WannaCrypt / Slammer / Moscow blackout 等）→ RAG + 评测 |
| **Loghub Apache** | [Zenodo Loghub](https://github.com/logpai/loghub) | ~257 KB | 系统日志样本 |
| **Loghub Linux** | 同上 | ~227 KB | 内核/认证失败等行样本 |
| **Loghub Zookeeper** | 同上 | ~449 KB | 分布式组件错误日志 |
| **Loghub SSH** | 同上 | ~4.4 MB | 认证失败 syslog 风格样本 |

原始压缩包在 `raw/`，解压在 `extracted/`，加工结果在 `processed/` 与 `eval/`。

## 目录结构

```
datasets/
  raw/                 # 下载的 zip/tar.gz
  extracted/           # 解压后的原始日志 / CSV
  processed/
    bgp_anomaly_summary.json
    log_samples.jsonl
    ssh_auth_failures_sample.log
  eval/
    golden_cases.jsonl # 258 条：171 合成电信 + 40 Loghub + 27 口语化难例 + 20 历史 BGP
```

`golden_cases.jsonl` 的四个分类：

| 分类 | 条数 | 说明 |
|------|------|------|
| `synthetic_telco` | 171 | 9 类故障 × FRR/Cisco/JunOS/SNMP/Nokia 措辞 × 多设备，标签与 Triage 分类表同源生成 |
| `loghub_adapted` | 40 | Loghub Linux/SSH 真实行，按 `rhost + user + 类型` 去重 |
| `paraphrased_hard` | 27 | 运维口语化改写，**不含厂商关键字**，用来暴露纯正则方案的边界 |
| `historical_bgp_anomaly` | 20 | SFU/RIPE 标注异常 + 公开事件（AS7007、YouTube 劫持、Facebook 2021 等） |

> `paraphrased_hard` 在离线规则下准确率为 0%，这是**故意**的对照组：如果不放这类样本，规则基线会因为「标签由同一套正则定义」而天然拿到 100%，消融就失去意义。

额外会生成：

```
knowledge/sops/historical_bgp_anomalies.md   # 可 ingest 进 Qdrant
```

## 一键下载 + 加工

```bash
source .venv/bin/activate
python scripts/download_datasets.py
python scripts/prepare_datasets.py

# 把历史 BGP SOP 灌进向量库
python pipeline_main.py ingest-sops

# 用黄金用例跑一条
python pipeline_main.py diagnose -m "$(head -n1 datasets/eval/golden_cases.jsonl | python -c 'import sys,json; print(json.load(sys.stdin)[\"syslog\"])')"
```

## 许可与引用

- **Loghub**：研究/学术用途，请引用 [logpai/loghub](https://github.com/logpai/loghub)
- **SFU BGP CSV**：来自 Zhida Li / Trajkovic 等公开研究数据；原始 BGP 来自 **RIPE RIS**
- **不要**把现网运营商私有 syslog 未经脱敏就提交到 git

## 和本平台的关系

```
公开 BGP 异常 CSV ──► historical_bgp_anomalies.md ──► RAG
公开系统日志      ──► log_samples / golden_cases   ──► 评测 / 注入 Syslog
Containerlab 实时 ──► fault_injector               ──► 真实闭环 Demo
```
