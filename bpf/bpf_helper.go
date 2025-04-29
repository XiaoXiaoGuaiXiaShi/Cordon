package bpf

import (
	"embed" 	// 将文件或者文件夹嵌入到Go的可执行文件中，这样就可以在运行时从这个可执行文件中读取嵌入的文件内容，而无需依赖额外的文件系统路径。
)


//go:embed bytecode
var EmbedFS embed.FS
