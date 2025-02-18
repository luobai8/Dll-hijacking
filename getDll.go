package tools

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// 常量定义
const (
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_READ           = 0x0010
	MAX_PATH                  = 260
)

var (
	psapi                   = syscall.NewLazyDLL("psapi.dll")
	procEnumProcessModules  = psapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx = psapi.NewProc("GetModuleFileNameExW")
)

func GetDll() {

	fmt.Println("  ____    _       _         _       _     _                  _      _                 ")
	fmt.Println(" |  _ \\  | |     | |       | |__   (_)   (_)   __ _    ___  | | __ (_)  _ __     __ _ ")
	fmt.Println(" | | | | | |     | |       | '_ \\  | |   | |  / _` |  / __| | |/ / | | | '_ \\   / _` |")
	fmt.Println(" | |_| | | |___  | |___    | | | | | |   | | | (_| | | (__  |   <  | | | | | | | (_| |")
	fmt.Println(" |____/  |_____| |_____|   |_| |_| |_|  _/ |  \\__,_|  \\___| |_|\\_\\ |_| |_| |_|  \\__, |")
	fmt.Println("                                       |__/                                     |___/ ")

	if len(os.Args) < 2 {
		fmt.Println("")

		color.Yellow("  usage: dll-hijacking.exe <PID>")
		fmt.Println("")

		color.Yellow("  请执行命令 tasklist 获取具体的进程PID值")
		fmt.Println("")

		return
	}

	input := os.Args[1]
	num, err := strconv.Atoi(input)
	if err != nil {
		fmt.Println("输入内容有误，请输入正确的数字:", err)

		return
	}

	color.Yellow("输入的进程PID：%d", num)

	// 获取进程 ID
	pid := uint32(num) // 示例 PID，替换为实际进程 ID

	// 尝试打开进程
	hProcess, err := syscall.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		fmt.Println("Failed to open process:", err)
		return
	}
	defer syscall.CloseHandle(hProcess)

	// 获取模块句柄列表
	var modules [1024]syscall.Handle
	var cbNeeded uint32
	ret, _, _ := procEnumProcessModules.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&modules[0])),
		uintptr(len(modules)*int(unsafe.Sizeof(modules[0]))),
		uintptr(unsafe.Pointer(&cbNeeded)),
	)

	if ret == 0 {
		fmt.Println("EnumProcessModules failed:", syscall.GetLastError())
		return
	}

	// 计算模块数量
	moduleCount := int(cbNeeded) / int(unsafe.Sizeof(modules[0]))

	// 遍历模块并获取模块路径
	for i := 0; i < moduleCount; i++ {
		var modulePath [MAX_PATH]uint16
		ret, _, _ := procGetModuleFileNameEx.Call(
			uintptr(hProcess),
			uintptr(modules[i]),
			uintptr(unsafe.Pointer(&modulePath[0])),
			uintptr(MAX_PATH),
		)

		if ret == 0 {
			fmt.Println("GetModuleFileNameEx failed:", syscall.GetLastError())
			continue
		}

		moduleName := syscall.UTF16ToString(modulePath[:])

		if i+1 == 1 {
			color.Yellow("捕获到进程：%s", moduleName)
			color.Yellow("依赖的 dll 文件如下")
			fmt.Println("----------------------------------------------------")

			continue
		}

		color.Green("%s\n", moduleName)
	}
}
