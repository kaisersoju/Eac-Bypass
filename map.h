#pragma once

namespace Map {
	PVOID ExtendMap(Comm::Process& process, PBYTE base, LPCWSTR module);
	PVOID ExtendMap(Comm::Process& process, LPCWSTR filePath, LPCWSTR module);
}