#pragma once

#include <memory>
#include <vtil/compiler>

namespace vtil
{
	struct basic_block;
	struct routine;
}
class AbstractStream;

extern void lift_insn(vtil::basic_block* block, const vtil::amd64::instruction& insn, bool no_flags = false);

struct themida_lifter
{
	themida_lifter(AbstractStream* stream);
	~themida_lifter();

	void load_native_routine(const std::filesystem::path& path);
	void save_native_routine(const std::filesystem::path& path);


private:
	void ldd(vtil::basic_block* block, const vtil::instruction& ins);
	void str(vtil::basic_block* block, const vtil::instruction& ins);

	vtil::basic_block* run_entry(vtil::basic_block* block);
	void lift_entry(vtil::basic_block* block, uint64_t entry_va);

public:
	vtil::basic_block* run_basic_block(vtil::basic_block* dest_block, const vtil::basic_block* source_block);
	vtil::basic_block* lift_native_block(uint64_t va);

public:
	// first handler address / lock address / bytecode
	vtil::basic_block* lift_entry(uint64_t va);

	vtil::basic_block* lift_handler(vtil::basic_block* block, uint64_t va);


private:
	AbstractStream* stream;

public:
	// stack pointer
	vtil::symbolic_vm* m_vm;

private:
	// themida context
	vtil::symbolic::memory* m_global_context;

	// routine for x86
	std::unique_ptr<vtil::routine> m_native_rtn;

public:
	// list of virtual registers
	std::list<vtil::register_desc> m_vregs;
};





/*namespace vtil::optimizer
{
	struct gpr_elimination_pass : pass_interface<vtil::optimizer::execution_order::parallel>
	{
		size_t pass(basic_block* blk, bool xblock = false) override;
	};
};*/