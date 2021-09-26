#include "pch.h"

#include "lifter.hpp"
#include "ProcessStream.hpp"

void themida_test()
{
	ProcessStream stream(true);
	if (!stream.open("devirtualizeme_tmd_2.4.6.0_tiger64.exe"))
		throw std::runtime_error("process not open");

	std::filesystem::path native_rtn_path(vtil::format::str("tiger64_native_routine.vtil"));
	themida_lifter lifter(&stream);

	if (std::filesystem::exists(native_rtn_path))
	{
		lifter.load_native_routine(native_rtn_path);
	}


	// handlers
	uint64_t va = 0x00000001407E2F9Eull;
	vtil::basic_block* native_block = lifter.lift_native_block(va);
	fassert(native_block->is_complete());

	// reset register state
	const vtil::register_desc rbp_desc = { vtil::register_physical, X86_REG_RBP, 64, 0 };
	lifter.m_vm->register_state.reset();
	lifter.m_vm->write_register(rbp_desc, 0x14076562dull);

	vtil::basic_block* tmd_insn_block = vtil::basic_block::begin(0x1337);
	tmd_insn_block->mov(rbp_desc, 0x14076562dull);
	for (int i = 0; i < 2; i++)
	{
		vtil::logger::log <vtil::logger::CON_BLU >("lift native block 0x%llx\n", va);
		native_block = lifter.lift_native_block(va);
		fassert(native_block->is_complete());
		vtil::debug::dump(native_block);

		// then run
		tmd_insn_block = lifter.run_basic_block(tmd_insn_block, native_block);
		fassert(tmd_insn_block->is_complete());

		// unroll [jmp imm]
		fassert(!tmd_insn_block->empty());
		const vtil::instruction& ins = tmd_insn_block->back();
		fassert(ins.base == &vtil::ins::jmp && ins.operands[0].is_immediate());
		va = ins.operands[0].imm().u64;
		tmd_insn_block->pop_back();
	}

	// debug
	{
		// jmp -> vexit to apply optimization
		auto& ins = tmd_insn_block->wback();
		if (ins.base == &vtil::ins::jmp) ins.base = &vtil::ins::vexit;

		constexpr bool optimization_on_handler = 1;
		if constexpr (optimization_on_handler)
		{
			auto vexit_operands = ins.operands[0];
			tmd_insn_block->pop_back();

			for (auto vreg : lifter.m_vregs)
			{
				tmd_insn_block->vpinr(vreg);
			}
			tmd_insn_block->vexit(vexit_operands);

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
				>{}(tmd_insn_block->owner);
			}
		}
		vtil::debug::dump(tmd_insn_block->owner);
	}

	lifter.save_native_routine(native_rtn_path);
}