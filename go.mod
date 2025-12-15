module ebpf-injector

go 1.21.0

require github.com/cilium/ebpf v0.14.0 // 或者是其他高于 v0.13.0 的版本

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.19.0 // indirect; 依赖库的版本也可能会更新
)
