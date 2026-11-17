# pairwise-ids-matcher

边界 IDS 一上高流量，签名匹配就开始丢包：多模式匹配只取第一个命中，重叠规则把更具体的告警吞掉；大小写和 URL 编码没有归一，变形攻击直接漏；TCP 流重组在乱序和重传时拼错边界，跨包关键字断成两段；规则没有按流方向区分，回包也触发入口规则；白名单只按源 IP， NAT 后整个出口都被静音。security/ids_matcher.py 是核心，tests/test_ids_matcher.py 15个红。要修的是：多规则命中；归一化；流重组；方向感知；白名单精细化。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
