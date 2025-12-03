# eBPF Proxy Protocol Injector

Automated eBPF-based network packet injector that intercepts TCP SYN packets on specified ports and prepends HAProxy's PROXY Protocol v2 headers.

## Features

- eBPF kernel-space packet interception
- Automatic PROXY Protocol v2 header injection
- Port range and single port configuration support
- Graceful shutdown with proper cleanup
- Automated Docker image building and pushing

## Quick Start

### Prerequisites

- Linux kernel ≥ 5.8
- Root or CAP_BPF privileges
- Interface must exist at runtime

### Building

Docker image will be automatically built and pushed on:
- Push to `main`, `master`, or `develop` branches
- Creation of version tags (e.g., `v1.0.0`)
- Pull requests (image built but not pushed)

### Usage

```bash
docker run --rm --privileged \
  ghcr.io/your-username/ebpf-injector:latest \
  eth0 "8080,2000-3000,39075"
```

**Arguments:**
- `eth0`: Network interface name
- `"8080,2000-3000,39075"`: Port configuration (single ports, ranges, or combinations)

### Configuration

#### GitHub Secrets (for Docker Hub push)

If pushing to Docker Hub, configure these secrets in your GitHub repository:
- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub password/token

## Workflows

### `docker-build.yml` (Recommended for GitHub Only)

Builds and pushes to GitHub Container Registry (GHCR):
- Auto-tagged by branch and git hash
- Uses GITHUB_TOKEN (no extra configuration needed)

### `docker-multi-registry.yml` (Advanced)

Pushes to both GHCR and Docker Hub:
- Requires Docker Hub credentials in secrets
- Useful for maximum distribution

## Image Tags

- `branch-name`: Branch-specific tag
- `v1.0.0`: Semantic version tag
- `v1.0`: Major.minor version tag
- `main-abc123def`: Git SHA-based tag

## Development

```bash
# Local build
docker build -t ebpf-injector:local .

# Local test
docker run --rm --privileged \
  -it ebpf-injector:local eth0 "8080"
```

## Debugging

Inside container, kernel traces available at:
```bash
cat /sys/kernel/debug/tracing/trace_pipe | grep bpf_printk
```

Check TC attachment:
```bash
tc filter show dev eth0 ingress
```

## Architecture

See [.github/copilot-instructions.md](.github/copilot-instructions.md) for detailed architecture and development patterns.

## License

GPL (required for eBPF)
