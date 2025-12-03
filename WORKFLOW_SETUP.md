# GitHub Actions 工作流配置指南

## 阿里云镜像仓库配置

本项目使用 GitHub Actions 自动构建并推送多架构镜像到阿里云镜像仓库。

## 前置条件

1. 阿里云账号和镜像仓库
2. GitHub Actions 密钥配置

## 配置步骤

### 1. 获取阿里云凭证

- 登录 [阿里云容器镜像服务](https://cr.console.aliyun.com/)
- 获取您的**用户名**和**密码**（或生成临时令牌）

### 2. 配置 GitHub Secrets

在 GitHub 仓库设置中添加密钥：

1. 打开 GitHub 仓库 → **Settings** → **Secrets and variables** → **Actions**
2. 点击 **New repository secret**，添加以下两个密钥：

| 密钥名称 | 值 |
|---------|-----|
| `USERNAME_ALI` | 阿里云用户名 |
| `PASSWORD_ALI` | 阿里云密码或令牌 |

### 3. 修改工作流配置

编辑 `.github/workflows/docker-build.yml` 中的环境变量：

```yaml
env:
  REGISTRY: registry.cn-hangzhou.aliyuncs.com  # 阿里云镜像仓库地址
  IMAGE_NAMESPACE: your-namespace              # 修改为你的命名空间
  IMAGE_NAME: ebpf-injector                    # 镜像名称
```

## 工作流触发条件

- **推送到 `master` 分支** → 自动构建并推送
- **手动触发** → 点击 Actions → Build and Push Multi-Arch Image to Aliyun → Run workflow

## 镜像标签规则

工作流会自动生成以下标签：

| 场景 | 标签示例 |
|-----|--------|
| 推送到 master | `latest`, `master`, `master-abc123def` |
| 推送标签 v1.0.0 | `v1.0.0`, `v1.0`, `v1`, `master-abc123def` |
| 提交到其他分支 | `branch-name`, `branch-name-abc123def` |

## 支持的架构

- `linux/amd64` (x86_64)
- `linux/arm64` (ARM64/Apple Silicon)

## 完整的推送 URL

镜像将推送到：
```
registry.cn-hangzhou.aliyuncs.com/your-namespace/ebpf-injector:latest
```

## 使用推送的镜像

```bash
docker pull registry.cn-hangzhou.aliyuncs.com/your-namespace/ebpf-injector:latest

# 运行
docker run --rm --privileged \
  registry.cn-hangzhou.aliyuncs.com/your-namespace/ebpf-injector:latest \
  eth0 "8080,2000-3000"
```

## 故障排除

### 1. 推送失败：认证错误
- 检查 `USERNAME_ALI` 和 `PASSWORD_ALI` 是否正确
- 确保凭证有权推送到该命名空间

### 2. 多架构构建超时
- 检查 GitHub Actions 配额
- 考虑只构建单个架构（修改 `platforms` 字段）

### 3. 查看构建日志
- 打开 GitHub 仓库 → **Actions** → 选择最新的 workflow run
- 点击 **Build and Push Multi-Arch Image** 查看详细日志

## 工作流配置说明

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```
- 确保同一分支只有一个实例运行，新推送会取消旧的构建

```yaml
platforms: linux/amd64,linux/arm64
```
- 支持构建多架构镜像，自动选择合适的架构

```yaml
push: true
```
- 每次推送到 `master` 都会自动推送到阿里云

## 环境变量定制

如需修改镜像存储位置或其他配置：

```yaml
env:
  REGISTRY: registry.cn-hangzhou.aliyuncs.com
  IMAGE_NAMESPACE: your-org/your-project
  IMAGE_NAME: ebpf-injector
```

然后在工作流中引用：
```yaml
tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAMESPACE }}/${{ env.IMAGE_NAME }}:latest
```
