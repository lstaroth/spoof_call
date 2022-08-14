#include <type_traits>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <algorithm>

void* GetGadget(const wchar_t* moduleName);
extern "C" void* NoStackShellcode();

namespace detail
{
	struct shell_params
	{
		const void* gadget;
		void* realfunction_addr;
		void* Nonvolatile_register;
		void* shellcode_retaddr;
		void* shellcode_fixstack;
	};
	
	template <typename RET>
	static inline RET shellcode_stub_arg6(const void* shell, void* shell_param, void* first = 0, void* second = 0, void* third = 0, void* forth = 0)
	{
		auto fn = (RET(*)(void*, void*, void*, void*, void*))(shell);
		return fn(shell_param, first, second, third, forth);
	}

	template <typename RET, typename... ARGS>
	static inline RET shellcode_stub(const void* shell, void* shell_param, ARGS... args)
	{
		auto fn = (RET(*)(void*, ARGS...))(shell);
		return fn(shell_param, args...);
	}

	template<typename RET, typename... ARGS>
	struct argument_remapper
	{
		static RET do_call(void* shell_param, ARGS... args)
		{
			if constexpr (sizeof...(args) >= 4)
			{
				return shellcode_stub<RET, ARGS...>(&NoStackShellcode, shell_param, args...);
			}
			else
			{
				return shellcode_stub_arg6<RET>(&NoStackShellcode, shell_param, (void*)args...);
			}
		}
	};

	template<typename T>	concept NOT_USE_XMM = !std::is_floating_point_v<T>;

	template <typename RET, typename... ARGS>
	struct FunctionTraits {
	};

	template <typename RET, typename... ARGS>
	struct FunctionTraits<RET(ARGS...)> {
	};

	template <typename RET, NOT_USE_XMM... ARGS>
	struct FunctionTraits<RET(ARGS...)> {
		static inline RET spoof_call(const void* gadget, RET(*fn)(ARGS...), ARGS... args)
		{
			shell_params param{ .gadget = gadget, .realfunction_addr = fn };
			return argument_remapper<RET, ARGS...>::do_call(&param, args...);
		}
	};
}

int64_t function(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f);

int main()
{
	void* gadget = nullptr;
	gadget = GetGadget(L"ntdll.dll");
	if (gadget)
	{
		const auto ret = detail::FunctionTraits<decltype(function)>::spoof_call(gadget, &function, 1, 2, 3, 4, 5, 6);
		std::cout << ret << std::endl;
	}
	return std::getchar();
}

int64_t function(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f)
{
	return a + b + c + d + e + f;
}

void* GetGadget(const wchar_t* moduleName)
{
	static const void* jmprbx = nullptr;
	if (!jmprbx) {
		const auto ntdll = reinterpret_cast<const unsigned char*>(::GetModuleHandleW(moduleName));
		const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
		const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(ntdll + dos->e_lfanew);
		const auto sections = IMAGE_FIRST_SECTION(nt);
		const auto num_sections = nt->FileHeader.NumberOfSections;

		constexpr char section_name[5]{ '.', 't', 'e', 'x', 't' };
		const auto section = std::find_if(sections, sections + num_sections, [&](const auto& s) {
			return std::equal(s.Name, s.Name + 5, section_name); });

		constexpr unsigned char instr_bytes[2]{ 0xFF, 0x23 };
		const auto va = ntdll + section->VirtualAddress;
		jmprbx = std::search(va, va + section->Misc.VirtualSize, instr_bytes, instr_bytes + 2);
	}
	return const_cast<void*>(jmprbx);
}