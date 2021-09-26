#include "pch.h"

#include "lifter.hpp"
#include "ProcessStream.hpp"

#pragma comment(linker, "/STACK:67108864")
#pragma comment(lib, "keystone.lib")
#pragma comment(lib, "capstone.lib")
#pragma comment(lib, "VTIL-Architecture.lib")
#pragma comment(lib, "VTIL-Common.lib")
#pragma comment(lib, "VTIL-Compiler.lib")
#pragma comment(lib, "VTIL-SymEx.lib")
#pragma comment(lib, "NativeLifters-Core.lib")

/*
 * Demonstrates basic simplification of a small "obfuscated" basic block
 * Deobfuscated this code would just be a series of "push N" instructions where N = {0..100}
 */

static constexpr vtil::register_desc make_virtual_register(uint8_t context_offset, uint8_t size)
{
	fassert(((context_offset & 7) + size) <= 8 && size);

	return {
		vtil::register_virtual,
		(size_t)context_offset / 8,
		size * 8,
		(context_offset % 8) * 8
	};
}

void vtil_symex()
{
	auto block = vtil::basic_block::begin(0x1337);
	std::map<vtil::symbolic::expression, vtil::register_desc> expressions;

	// tmp = vr
	vtil::symbolic::expression op1 = { {"op1"}, 4 };
	auto _d = op1 + 123;
}

void vtil_block()
{
	auto block = vtil::basic_block::begin(0x1337);
	vtil::register_desc VM_REG_75(vtil::register_local, 0x75, 32, 0);
	vtil::register_desc VM_REG_3C(vtil::register_local, 0x3C, 32, 0);

	auto [t25626, t25627, t25629, t25631, t25633, t25635, t25637, t25639, t25640] = block->tmp(32, 32, 32, 32, 32, 32, 32, 32, 32);

	vtil::logger::log("t25626 is local: %d\n", t25626.is_local());

	block->shift_sp(-4);

	block->label_begin(0xdb7a56);
	block->mov(t25626, VM_REG_75)
		->mov(t25627, t25626)
		->add(t25627, 0x13f7df62)
		->mov(t25629, t25627)
		->add(t25629, 0xdaf98ac9)
		->mov(t25631, t25629)
		->add(t25631, 0x42c31feb)
		->mov(t25633, t25631)
		->sub(t25633, 0x42c31feb)
		->mov(t25635, t25633)
		->sub(t25635, 0xdaf98ac9)
		->mov(t25637, t25635)
		->sub(t25637, 0x13f7df62)
		->push(t25637)
		->mov(t25639, VM_REG_3C)
		->mov(t25640, t25639)
		->sub(t25640, 0x4)
		->mov(VM_REG_3C, t25640);
	block->label_end();


	//block->vpinr(VM_REG_3C);      // pin register eax as read so it doesn't get optimized away
	//block->vexit(0ull); // marks the end of a basic_block

	vtil::logger::log(":: Before:\n");
	vtil::debug::dump(block->owner);

	vtil::logger::log("\n");

	// executes all optimization passes
	vtil::optimizer::apply_all_profiled(block->owner);
	//vtil::optimizer::fast_local_dead_code_elimination_pass{}.pass(block);

	vtil::logger::log("\n");

	vtil::logger::log(":: After:\n");
	vtil::debug::dump(block->owner);
}


void tiger64_white()
{
	ProcessStream stream(true);
	if (!stream.open("devirtualizeme_tmd_2.4.6.0_tiger64.exe"))
		throw std::runtime_error("process not open");


	std::filesystem::path native_rtn_path(vtil::format::str("tiger64_native_routine.vtil"));
	themida_lifter lifter(&stream);



	// lift entry
	//vtil::basic_block* entry_block = lifter.lift_entry(0x140001D37ull);
	vtil::basic_block* entry_block = lifter.lift_entry(0x140942C82ull); // last one
	if (std::filesystem::exists(native_rtn_path))
	{
		lifter.load_native_routine(native_rtn_path);
	}

	// assume basic block ends with "vexit imm" -> "jmp imm"
	auto& ins = entry_block->wback();
	fassert(ins.base == &vtil::ins::vexit && ins.operands[0].is_immediate());
	ins.base = &vtil::ins::jmp;


	// handlers
	vtil::basic_block* prev_block = entry_block;
	uint64_t va = ins.operands[0].imm().u64;;
	for (int i = 0; i < 24; i++)
	{
		// lift handler
		prev_block = lifter.lift_handler(prev_block, va);

		// assume last instruction is [jmp imm]
		const auto& ins = prev_block->back();
		fassert(ins.base == &vtil::ins::jmp && ins.operands[0].is_immediate());
		va = ins.operands[0].imm().u64;
	}

	// debug
	{
		// jmp -> vexit to apply optimization
		auto& ins = prev_block->wback();
		if (ins.base == &vtil::ins::jmp) ins.base = &vtil::ins::vexit;

		constexpr bool optimization_on_handler = 1;
		if constexpr (optimization_on_handler)
		{
			auto vexit_operands = ins.operands[0];
			prev_block->pop_back();

			for (auto vreg : lifter.m_vregs)
			{
				prev_block->vpinr(vreg);
			}
			prev_block->vexit(vexit_operands);

			if (1)
			{
				/*vtil::optimizer::apply_each<
					vtil::optimizer::profile_pass,
					vtil::optimizer::collective_local_pass
				>{}(entry_block->owner);*/
			}
			else
			{
				vtil::optimizer::apply_each<
					vtil::optimizer::profile_pass,
					vtil::optimizer::combine_pass<
					vtil::optimizer::collective_local_pass
					//,vtil::optimizer::gpr_elimination_pass
					//vtil::optimizer::dead_code_elimination_pass,

					// merge blocks
					//, vtil::optimizer::bblock_extension_pass
					>
				>{}(entry_block->owner);
			}
		}
		vtil::debug::dump(entry_block->owner);
	}

	lifter.save_native_routine(native_rtn_path);
}


void vtil_test()
{
	// block1
	auto block = vtil::basic_block::begin(0x1337);
	block->pushf();
	block->pushf();
	block->pushf();
	vtil::debug::dump(block->owner);
	vtil::logger::log("\n\n\n");

	{
		int64_t sp_offset_old = 0;
		auto block2 = vtil::basic_block::begin(0x13372);
		for (auto it = block->begin(); it != block->end(); ++it)
		{
			auto& ins = *it;
			vtil::logger::log("%s (%d %d)\n", ins.to_string(), ins.sp_index, ins.sp_offset);

			const int64_t sp_offset = ins.sp_offset - sp_offset_old;
			if (sp_offset)
			{
				block2->shift_sp(sp_offset);
			}
			block2->push_back(ins);
			sp_offset_old = ins.sp_offset;
		}
		vtil::debug::dump(block2->owner);
	}
}

static void vtil_opt_test()
{
	auto block = vtil::basic_block::begin(0x1337);
	block->push(vtil::make_imm<uint64_t>(0x1337));
	block->jmp(1ull);

	// store_operand( block, insn, 0, load_operand( block, insn, 1 ) );
	auto block2 = block->fork(1ull);
	block2->ldd(X86_REG_RAX, vtil::REG_SP, 0);
	block2->add(vtil::REG_SP, 8);
	block2->vpinr(X86_REG_RAX);
	block2->vexit(0ull); // marks the end of a basic_block




	vtil::logger::log(":: Before:\n");
	vtil::debug::dump(block->owner);

	vtil::logger::log("\n");

	vtil::optimizer::apply_each<
		vtil::optimizer::profile_pass,
		vtil::optimizer::collective_cross_pass
	>{}(block->owner);      // executes all optimization passes

	vtil::logger::log("\n");

	vtil::logger::log(":: After:\n");
	vtil::debug::dump(block->owner);
}

extern void themida_test();
int main()
{
	//vtil_test();
	//vtil_opt_test();
	themida_test();
	//tiger64_white();

	return 0;
}