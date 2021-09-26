#include "pch.h"

#include "lifter.hpp"
#include "insn.hpp"
#include "ProcessStream.hpp"

// vtil
#include <lifters/core>
#include <lifters/amd64>
#pragma comment(linker, "/STACK:67108864")

using namespace vtil;

extern std::list<noncopyable_insn>& reverse_trace_eflags(std::list<noncopyable_insn>& instructions);


//
#include "insn.hpp"


// read flags -> set of write flags
static std::set<uint64_t> get_write_flags_combined(uint64_t eflags)
{
	std::set<uint64_t> ret;
	if (eflags & X86_EFLAGS_TEST_AF)
	{
		ret.insert(X86_EFLAGS_MODIFY_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_UNDEFINED_AF);
	}
	if (eflags & X86_EFLAGS_TEST_CF)
	{
		ret.insert(X86_EFLAGS_MODIFY_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_UNDEFINED_CF);
	}
	if (eflags & X86_EFLAGS_TEST_SF)
	{
		ret.insert(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_UNDEFINED_SF);
	}
	if (eflags & X86_EFLAGS_TEST_ZF)
	{
		ret.insert(X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_UNDEFINED_ZF);
	}
	if (eflags & X86_EFLAGS_TEST_PF)
	{
		ret.insert(X86_EFLAGS_MODIFY_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_UNDEFINED_PF);
	}
	if (eflags & X86_EFLAGS_TEST_OF)
	{
		ret.insert(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_UNDEFINED_OF);
	}
	if (eflags & X86_EFLAGS_TEST_TF)
	{
		ret.insert(X86_EFLAGS_MODIFY_TF | X86_EFLAGS_RESET_TF);
	}
	if (eflags & X86_EFLAGS_TEST_DF)
	{
		ret.insert(X86_EFLAGS_MODIFY_DF | X86_EFLAGS_SET_DF | X86_EFLAGS_RESET_DF);
	}
	if (eflags & X86_EFLAGS_TEST_NT)
	{
		ret.insert(X86_EFLAGS_MODIFY_NT | X86_EFLAGS_RESET_NT);
	}
	if (eflags & X86_EFLAGS_TEST_RF)
	{
		ret.insert(X86_EFLAGS_MODIFY_RF | X86_EFLAGS_RESET_RF);
	}
	return ret;
}


// update alive_eflags
static std::list<noncopyable_insn>& reverse_trace_eflags(std::list<noncopyable_insn>& instructions)
{
	// all flags are considered 'alive' when it exits basic block
	std::set<uint64_t> read_flags = get_write_flags_combined(0xFFFFFFFFFFFFFFFF);
	for (auto it = instructions.rbegin(); it != instructions.rend(); ++it)
	{
		noncopyable_insn& insn = *it;
		insn.alive_eflags = read_flags;

		// remove if the instruction writes correspond flag
		for (auto flags_it = read_flags.begin(); flags_it != read_flags.end();)
		{
			if (insn->eflags & (*flags_it))
				flags_it = read_flags.erase(flags_it);
			else
				++flags_it;
		}

		// merge em
		read_flags.merge(get_write_flags_combined(insn->eflags));
	}
	
	return instructions;
}


//
themida_lifter::themida_lifter(AbstractStream* stream) : stream(stream)
{
	this->m_vm = new vtil::symbolic_vm;
	this->m_global_context = new vtil::symbolic::memory;
}
themida_lifter::~themida_lifter()
{
	delete this->m_vm;
	delete this->m_global_context;
}


void themida_lifter::load_native_routine(const std::filesystem::path& path)
{
	this->m_native_rtn.reset(vtil::load_routine(path));
	this->m_native_rtn->context.get<vtil::lifter::processing_flags>() = { .inline_calls = true };
}
void themida_lifter::save_native_routine(const std::filesystem::path& path)
{
	vtil::save_routine(this->m_native_rtn.get(), path);
}


// x86 -> VTIL
void lift_insn(basic_block* block, const amd64::instruction& insn, bool no_flags)
{
	// this significantly reduces computation cost
	if (no_flags
		&& (insn.id == X86_INS_ADD
			|| insn.id == X86_INS_SUB
			|| insn.id == X86_INS_AND
			|| insn.id == X86_INS_XOR
			|| insn.id == X86_INS_OR
			|| insn.id == X86_INS_SHL
			|| insn.id == X86_INS_SHR
			|| insn.id == X86_INS_INC
			|| insn.id == X86_INS_DEC
			|| insn.id == X86_INS_NEG))
	{
		batch_translator translator = { block };
		lifter::operative::translator = &translator;
		switch (insn.id)
		{
			case X86_INS_ADD:
			{
				auto lhs = lifter::amd64::load_operand(block, insn, 0);
				auto rhs = lifter::amd64::load_operand(block, insn, 1);
				auto tmp = block->tmp(lhs.bit_count());
				block->mov(tmp, lhs)->add(tmp, rhs);
				lifter::amd64::store_operand(block, insn, 0, tmp);
				break;
			}
			case X86_INS_SUB:
			{
				auto lhs = lifter::amd64::load_operand(block, insn, 0);
				auto rhs = lifter::amd64::load_operand(block, insn, 1);
				auto tmp = block->tmp(lhs.bit_count());
				block->mov(tmp, lhs)->sub(tmp, rhs);
				lifter::amd64::store_operand(block, insn, 0, tmp);
				break;
			}
			case X86_INS_AND:
			{
				auto lhs = lifter::amd64::load_operand(block, insn, 0);
				auto rhs = lifter::amd64::load_operand(block, insn, 1);
				auto tmp = block->tmp(lhs.bit_count());
				block->mov(tmp, lhs)->band(tmp, rhs);
				lifter::amd64::store_operand(block, insn, 0, tmp);
				break;
			}
			case X86_INS_XOR:
			{
				auto lhs = lifter::amd64::load_operand(block, insn, 0);
				auto rhs = lifter::amd64::load_operand(block, insn, 1);
				auto tmp = block->tmp(lhs.bit_count());
				block->mov(tmp, lhs)->bxor(tmp, rhs);
				lifter::amd64::store_operand(block, insn, 0, tmp);
				break;
			}
			case X86_INS_OR:
			{
				auto lhs = lifter::amd64::load_operand(block, insn, 0);
				auto rhs = lifter::amd64::load_operand(block, insn, 1);
				auto tmp = block->tmp(lhs.bit_count());
				block->mov(tmp, lhs)->bor(tmp, rhs);
				lifter::amd64::store_operand(block, insn, 0, tmp);
				break;
			}
			case X86_INS_SHL:
			{
				auto lhs = lifter::operative(lifter::amd64::load_operand(block, insn, 0));
				auto rhs = lifter::operative(lifter::amd64::load_operand(block, insn, 1));
				auto result = (lhs << (rhs & (lhs.op.size() == 8 ? 0x3F : 0x1F))).op;
				lifter::amd64::store_operand(block, insn, 0, result);
				break;
			}
			case X86_INS_SHR:
			{
				auto lhs = lifter::operative(lifter::amd64::load_operand(block, insn, 0));
				auto rhs = lifter::operative(lifter::amd64::load_operand(block, insn, 1));
				auto result = (lhs >> (rhs & (lhs.size() == 8 ? 0x3F : 0x1F))).op;
				lifter::amd64::store_operand(block, insn, 0, result);
				break;
			}
			case X86_INS_INC:
			{
				auto lhs = lifter::operative(lifter::amd64::load_operand(block, insn, 0));
				auto result = lhs + 1;
				lifter::amd64::store_operand(block, insn, 0, result);
				break;
			}
			case X86_INS_DEC:
			{
				auto lhs = lifter::operative(lifter::amd64::load_operand(block, insn, 0));
				auto result = lhs - 1;
				lifter::amd64::store_operand(block, insn, 0, result);
				break;
			}
			case X86_INS_NEG:
			{
				auto lhs = lifter::operative(lifter::amd64::load_operand(block, insn, 0));
				auto result = 0 - lhs;
				lifter::amd64::store_operand(block, insn, 0, result);
				break;
			}
			default:
			{
				unreachable();
			}
		}
	}
	else
	{
		// lift x86 -> IL
		lifter::amd64::lifter_t::process(block, insn.address, insn);
	}
}


void themida_lifter::ldd(vtil::basic_block* block, const vtil::instruction& ins)
{
	// ldd dest base off (dest<=[base+off])
	auto [base, off] = ins.memory_location();
	if (base.is_stack_pointer())
	{
		// if stack pointer normally execute instruction
		vtil::vm_exit_reason exit_reason = this->m_vm->execute(ins);
		block->push_back(ins);
		return;
	}

	// get address
	constexpr bool trace_base = true;
	uint64_t mem_loc;
	if constexpr (trace_base)
	{
		vtil::tracer _tracer = {};
		auto res = _tracer.rtrace_p(
			{ block->end(), base }
		);

		if (!res->is_constant())
		{

			logger::log<logger::CON_RED>("ldd %s is not constant\n", res->to_string());
			vtil::optimizer::apply_each<
	vtil::optimizer::profile_pass,
	vtil::optimizer::collective_local_pass
>{}(block->owner);
			vtil::debug::dump(block);
			fassert(res->is_constant());
		}
		mem_loc = *res->get() + off;
	}
	else
	{
		symbolic::expression mem_loc_exp = this->m_vm->read_register(base) + off;
		mem_loc = *mem_loc_exp.get<>();
	}

	symbolic::expression::reference ptr_ref(mem_loc, 64);
	uint64_t contains = 0;
	auto exp = this->m_global_context->read(
		ptr_ref, ins.operands[0].bit_count(), symbolic::free_form_iterator, &contains);

	// checks bits instead?
	if (contains == 0)
	{
		// read value from stream
		uint64_t val = 0;
		stream->seek(mem_loc);
		stream->read(&val, 8);
		val &= math::fill(ins.operands[0].bit_count());

		logger::log<logger::CON_GRN>("\tldd 0x%llx undefined %llx\n", mem_loc, val);

		// reg = val
		this->m_vm->write_register(ins.operands[0].reg(), val);

		// insert mov instead of ldd
		block->mov(
			ins.operands[0].reg(),
			vtil::operand(val, ins.operands[0].bit_count())
		);
	}
	else
	{
		logger::log<logger::CON_GRN>("\tldd 0x%llx defined: %s\n", mem_loc, exp->to_string());

		// memory is defined
		this->m_vm->write_register(ins.operands[0].reg(), exp);

		// expression -> operand what if not constant tho
		if (exp->is_constant())
		{
			block->mov(
				ins.operands[0].reg(),
				*exp->get()
			);
		}
		else
		{
			// hmmm
			//logger::log<logger::CON_RED>("\tldd not constant %s\n", exp->to_string());

			// mov dest, vr?
			const uint64_t reg_id = mem_loc - 0x14076562d;
			vtil::register_desc reg_desc = { vtil::register_virtual, reg_id, 64, 0 };
			block->mov(ins.operands[0], reg_desc);
		}
	}
}


void themida_lifter::str(vtil::basic_block* block, const vtil::instruction& ins)
{
	auto [base, off] = ins.memory_location();
	if (base.is_stack_pointer())
	{
		// if stack pointer normally execute instruction
		vtil::vm_exit_reason exit_reason = this->m_vm->execute(ins);
		block->push_back(ins);
		return;
	}

	auto mem_loc_exp = this->m_vm->read_register(base) + off;
	fassert(mem_loc_exp.is_constant());
	const uint64_t mem_loc = *mem_loc_exp.get();

	// let it execute
	const auto& source_op = ins.operands[2];
	const bitcnt_t aligned_size = (source_op.bit_count() + 7) & ~7;
	const vtil::deferred_result source_value = [&]() -> symbolic::expression::reference
	{
		symbolic::expression::reference source_exp;
		if (source_op.is_register())
		{
			source_exp = this->m_vm->read_register(source_op.reg());
			if (source_op.reg().is_stack_pointer())
				source_exp = source_exp + ins.sp_offset;
		}
		else
		{
			fassert(source_op.is_immediate());
			source_exp = { source_op.imm().i64, source_op.imm().bit_count };
		}
		source_exp.resize(aligned_size);
		return source_exp;
	};


	// update global context
	auto exp_ref = this->m_global_context->write(
		//symbolic::pointer{ 
		symbolic::expression::reference{ mem_loc, 64 }
		//}
	, source_value, aligned_size);
	fassert(exp_ref.has_value());

	symbolic::expression::reference ref = *exp_ref;
	logger::log<logger::CON_GRN>("\tstr 0x%llx <- %s\n", mem_loc, source_value->to_string());

	// hmmm
	const uint64_t reg_id = mem_loc - 0x000000014076562DLL; // 000000014076562D
	// flag, cid, bit_count bit_offset
	vtil::register_desc reg_desc = { vtil::register_virtual, reg_id, 64, 0 };
	block->mov(reg_desc, source_op);
	this->m_vregs.push_back(reg_desc);
}


vtil::basic_block* themida_lifter::run_entry(vtil::basic_block* block)
{
	// concrete ldd/str to simplify
	int64_t sp_offset_old = 0;
	vtil::basic_block* block_concretized = vtil::basic_block::begin(block->entry_vip);
	for (auto it = block->begin(); it != block->end(); ++it)
	{
		const vtil::instruction& ins = *it;
		//logger::log("%s\n", ins.to_string());


		if (ins.base == &ins::ldd)
		{
			this->ldd(block_concretized, ins);
		}
		else if (ins.base == &ins::str)
		{
			this->str(block_concretized, ins);
		}
		else if (ins.base == &ins::js || ins.base == &ins::jmp || ins.base == &ins::vxcall)
		{
			unreachable();
		}
		else
		{
			vtil::vm_exit_reason exit_reason = this->m_vm->execute(ins);
			const int64_t sp_offset = ins.sp_offset - sp_offset_old;
			if (sp_offset)
			{
				block_concretized->shift_sp(sp_offset);
			}
			block_concretized->push_back(ins);
			sp_offset_old = ins.sp_offset;
		}
	}

	// optimize
	optimizer::apply_all_profiled(block_concretized->owner);
	//debug::dump(block_concretized->owner);

	// check stacks
	vtil::tracer tracer = {};

	// REG_SP before execution
	auto stack_0 = vtil::symbolic::variable(block_concretized->begin(), vtil::REG_SP).to_expression();
	logger::log<logger::CON_GRN>("stack_0: %s\n", stack_0.to_string());

	// REG_SP after execution
	auto stack_1 = tracer.trace_p({ block_concretized->end(), vtil::REG_SP }) + block_concretized->sp_offset;
	logger::log<logger::CON_GRN>("stack_1: %s\n", stack_1.to_string());

	auto offset = stack_1 - stack_0;
	logger::log<logger::CON_GRN>("stack_offset: %s\n", offset.to_string());
	fassert(offset.is_constant());


	constexpr size_t stack_size = 8;
	const size_t var_length = (-offset.get<int64_t>().value()) / stack_size;
	for (size_t i = 0; i < var_length; i++)
	{
		vtil::symbolic::pointer ptr(stack_0 - (stack_size + stack_size * i));
		auto exp_ref = tracer.trace_p(
			// const symbolic::variable& lookup
			{
				// iterator
				block_concretized->end(),

				// memory_t
				{ ptr, 64 }
			}
		);
		logger::log("%d: %s\n", i, exp_ref->to_string());
	}


	return block_concretized;
}


void themida_lifter::lift_entry(basic_block* block, uint64_t entry_va)
{
	stream->seek(entry_va);
	for (;;)
	{
		const noncopyable_insn insn = stream->next();

		// lock cmpxchg [mem], ecx
		if (insn->prefix[0] == X86_PREFIX_LOCK
			&& insn->is(X86_INS_CMPXCHG, { X86_OP_MEM, X86_OP_REG }))
		{
			// -> str
			//auto lhs = lifter::amd64::load_operand(block, insn, 0);
			auto rhs = lifter::amd64::load_operand(block, insn, 1);
			lifter::amd64::store_operand(block, insn, 0, rhs);

			// ZF=1
			const register_desc ZF = { register_physical | register_flags, 0, 1, 6 };
			block->mov(ZF, 1);

			// save base and index maybe?
			//const auto& mem_op = insn->operands[0].mem;
			continue;
		}

		lift_insn(block, insn, true);
		if (!block->is_complete())
		{
			continue;
		}

		vtil::instruction& ins = block->wback();
		if (ins.base == &ins::jmp && ins.operands[0].is_immediate())
		{
			// unroll jmp imm
			const uint64_t imm = ins.operands[0].imm().u64;
			block->pop_back();
			stream->seek(imm);
		}
		else if (ins.base == &ins::js)
		{
			fassert(ins.operands[1].is_immediate());

			// follow jcc and unroll (it should work unless oreans changes behavior)
			const uint64_t imm = ins.operands[1].imm().u64;
			block->pop_back();
			stream->seek(imm);
		}
		else
		{
			// jmp reg is expected
			fassert(ins.base == &ins::jmp && ins.operands[0].is_register());

			// convert to vexit
			ins.base = &ins::vexit;
			break;
		}
	}
}


vtil::basic_block* themida_lifter::lift_entry(uint64_t va)
{
	std::filesystem::path rtn_optimized_path(vtil::format::str("entry-%llX.optimized.vtil", va));
	std::filesystem::path rtn_premature_path(vtil::format::str("entry-%llX.premature.vtil", va));

	// load routine from file if avaiable
	routine* entry_rtn = nullptr;
	if (std::filesystem::exists(rtn_optimized_path))
	{
		// load optimized routine
		entry_rtn = vtil::load_routine(rtn_optimized_path);
	}
	else
	{
		if (std::filesystem::exists(rtn_premature_path))
		{
			// load premature routine
			entry_rtn = vtil::load_routine(rtn_premature_path);
		}
		else
		{
			basic_block* block = basic_block::begin(va);
			entry_rtn = block->owner;
			entry_rtn->context.get<vtil::lifter::processing_flags>() = { .inline_calls = true };
			//rtn->routine_convention = {};
			entry_rtn->routine_convention.purge_stack = true;

			// lift
			this->lift_entry(block, va);

			// save premature routine
			vtil::save_routine(entry_rtn, rtn_premature_path);
		}

		// apply simplification
		optimizer::apply_all_profiled(entry_rtn);

		// save optimized routine
		vtil::save_routine(entry_rtn, rtn_optimized_path);
	}
	//debug::dump(entry_rtn);


	// vmentry should be straightforward
	fassert(entry_rtn->num_blocks() == 1);


	basic_block* lifted_block = this->run_entry(entry_rtn->entry_point);
	vtil::debug::dump(lifted_block->owner);

	// reset register state after execution
	/*vtil::register_desc rbp_desc = { vtil::register_physical, X86_REG_RBP, 64, 0 };
	auto rbp_exp = this->m_vm->read_register(rbp_desc);
	this->m_vm->register_state.reset();
	this->m_vm->write_register(rbp_desc, rbp_exp);*/

	this->m_native_rtn.reset(entry_rtn);
	this->m_native_rtn->context.get<vtil::lifter::processing_flags>() = { .inline_calls = true };

	return lifted_block;
}


vtil::basic_block* themida_lifter::run_basic_block(vtil::basic_block* dest_block, const vtil::basic_block* source_block)
{
	int64_t sp_offset_old = 0;
	for (auto iter = source_block->begin(); iter != source_block->end(); iter++)
	{
		const vtil::instruction& ins = *iter;
		//logger::log("%s\n", ins.to_string());

		/*if (ins.sp_reset)
		{
			dest_block->shift_sp(-ins.sp_offset, false, it);
			dest_block->sp_index = 0;
		}*/

		const int64_t sp_offset = ins.sp_offset - sp_offset_old;
		if (sp_offset)
		{
			//dest_block->shift_sp(sp_offset);
		}

		if (ins.base == &ins::ldd)
		{
			this->ldd(dest_block, ins);
		}
		else if (ins.base == &ins::str)
		{
			this->str(dest_block, ins);
		}
		else if (ins.base == &ins::js)
		{
			// everything should be constant at runtime
			symbolic::expression::reference cond_ref = this->m_vm->read_register(ins.operands[0].reg());
			fassert(cond_ref->is_constant());

			// insert jmp
			const bool cond = *cond_ref->get();
			const uint64_t next_vip = (cond ? ins.operands[1].imm() : ins.operands[2].imm()).u64;
			dest_block->jmp(next_vip);
			logger::log<logger::CON_PRP>("\tjs path taken: 0x%llx\n", next_vip);
			break;
		}
		else if (ins.base == &ins::jmp)
		{
			if (ins.operands[0].is_immediate())
			{
				const uint64_t next_vip = ins.operands[0].imm().u64;
				dest_block->jmp(next_vip);
			}
			else
			{
				dest_block->push_back(ins);
				vtil::tracer tracer = {};
				auto lbranch_info = optimizer::aux::analyze_branch(
					dest_block,
					&tracer,
					{ .cross_block = true, .pack = true, .resolve_opaque = true }
				);
				fassert(lbranch_info.destinations.size() == 1);

				const auto& branch = lbranch_info.destinations[0];
				if (branch->is_constant())
				{
					const auto branch_imm = *branch->get<vip_t>();
					dest_block->wback().operands = { branch_imm };
				}
				else
				{
					// to vexit
					fassert(1);
				}
			}

			break;
		}
		else if (ins.base == &ins::vexit)
		{
			const auto& op0 = ins.operands[0];
			if (op0.is_immediate())
			{
				// imm
				dest_block->jmp(op0.imm().u64);
			}
			else
			{
				// reg
				auto exp_ref = this->m_vm->read_register(op0.reg());
				fassert(exp_ref->is_constant());
				dest_block->jmp(exp_ref->get().value());
			}

			break;
		}
		else
		{
			// execute
			const vtil::vm_exit_reason exit_reason = this->m_vm->execute(ins);
			if (exit_reason == vtil::vm_exit_reason::none)
			{
				dest_block->push_back(ins);
			}
			else if (exit_reason == vtil::vm_exit_reason::alias_failure)
			{
				auto [base, off] = ins.memory_location();
				vtil::tracer tracer;
				auto exp_ref = tracer.trace_p({ iter, base });
				logger::log("\talias_failure: %s\n", (exp_ref + off).to_string());
			}
			else
			{
				uint32_t r = static_cast<uint32_t>(exit_reason);
				logger::log<logger::CON_RED>("vm exit with: %d, %s\n", r, ins.to_string());
				dest_block->push_back(ins);
				break;
			}
		}

		sp_offset_old = ins.sp_offset;
	}

	return dest_block;
}


vtil::basic_block* themida_lifter::lift_native_block(uint64_t va)
{
	if (!this->m_native_rtn)
	{
		auto block = vtil::basic_block::begin(0);
		this->m_native_rtn.reset(block->owner);
		this->m_native_rtn->context.get<vtil::lifter::processing_flags>() = { .inline_calls = true };
	}
	fassert(this->m_native_rtn != nullptr);

	auto block = this->m_native_rtn->find_block(va);
	if (block)
	{
		// return existing
		logger::log<logger::CON_YLW>("return existing block 0x%llx\n", va);
		return block;
	}


	// split block if possible (cannot do this rn because block is modified by optimizer)
	/*for (const auto& pair : this->m_native_rtn->explored_blocks)
	{
		block = pair.second;
		auto& bb_ctx = basic_block_ctx(block);
		if (bb_ctx.contains(va))
		{
			// create new basic block
			vtil::basic_block* new_block = this->m_native_rtn->create_block(va, block).first;

			// copy instructions
			const il_const_iterator ins_begin = bb_ctx.pos.at(va);
			const il_const_iterator ins_end = block->end();
			new_block->assign(ins_begin, ins_end);

			// init ctx
			auto& new_bb_ctx = basic_block_ctx(new_block);
			new_bb_ctx.leader = va;
			new_bb_ctx.next = bb_ctx.next;

			// modify previous basic block
			auto pos = ins_begin;
			while (pos != block->end())
			{
				pos = block->erase(pos);
			}

			block->jmp(va);
			bb_ctx.next = va;

			// not sure how it works
			//block->owner->flush_paths();

			return new_block;
		}
	}*/


	// create basic block
	block = this->m_native_rtn->create_block(va).first;

	auto& bb_context = basic_block_ctx(block);
	bb_context.leader = va;


	// lift
	stream->seek(va);
	for (;;)
	{
		// disasm
		noncopyable_insn insn = stream->next();
		//logger::log("%s\n", insn->to_string());

		// all jump instructions (conditional+direct+indirect jumps)
		if (insn->in_group(X86_GRP_JUMP)
			// all call instructions
			|| insn->in_group(X86_GRP_CALL)
			// all return instructions
			|| insn->in_group(X86_GRP_RET))
		{
			// if jmp imm queue pls
			if (insn->is(X86_INS_JMP, { X86_OP_IMM }))
			{
				// cant do forward-trace but can do reverse trace
				//const uint64_t vip = insn->operands[0].imm;
				//vtil::basic_block* target_block = lift_native_block(vip);
			}
			else if (insn->is(X86_INS_CALL, { X86_OP_IMM }))
			{
				// inline call imm pls.
			}
			bb_context.amd64_instructions.emplace_back(std::move(insn));

			// if CFG instruction is detected, lift to VTIL
			for (const noncopyable_insn& _insn : reverse_trace_eflags(bb_context.amd64_instructions))
			{
				if (block->empty())
				{
					lift_insn(block, _insn, _insn.alive_eflags.empty());
					bb_context.pos[_insn->address] = block->begin();
				}
				else
				{
					auto it = std::prev(block->end());
					lift_insn(block, _insn, _insn.alive_eflags.empty());
					bb_context.pos[_insn->address] = std::next(it);
				}
			}
			fassert(block->is_complete());

			// jmp reg -> vexit?
			auto& branch_ins = block->wback();
			if (branch_ins.base == &ins::jmp
				&& !branch_ins.operands[0].is_immediate())
			{
				branch_ins.base = &ins::vexit;
			}

			// finish
			break;
		}
		else
		{
			fassert(!insn->in_group(X86_GRP_INT) && !insn->in_group(X86_GRP_IRET));
			bb_context.amd64_instructions.emplace_back(std::move(insn));
		}
	}


	// remove temp variables
	vtil::optimizer::apply_each<
		vtil::optimizer::profile_pass,
		vtil::optimizer::collective_local_pass
	>{}(block);
	vtil::optimizer::apply_each<
		vtil::optimizer::profile_pass,
		vtil::optimizer::combine_pass<
		vtil::optimizer::fast_local_dead_code_elimination_pass,
		vtil::optimizer::fast_reg_propagation_pass,
		vtil::optimizer::zero_pass<vtil::optimizer::fast_local_dead_code_elimination_pass>
		>
	>{}(block);


	// dbg
	std::ofstream _fstream;
	_fstream.open(vtil::format::str("%llx.txt", bb_context.leader));
	for (auto &insn : bb_context.amd64_instructions)
	{
		_fstream << insn->to_string() << '\n';
	}

	bb_context.next = stream->pos();
	return block;
}


vtil::basic_block* themida_lifter::lift_handler(vtil::basic_block* block, uint64_t va)
{
	// reset register state
	const vtil::register_desc rbp_desc = { vtil::register_physical, X86_REG_RBP, 64, 0 };
	auto rbp_exp = this->m_vm->read_register(rbp_desc);
	fassert(rbp_exp->is_constant());
	this->m_vm->register_state.reset();
	this->m_vm->write_register(rbp_desc, rbp_exp);

	static vip_t pcode = 0;
	vip_t next_pcode = ++pcode;

	// jmp va -> jmp pcode
	{
		auto& ins = block->wback();
		fassert(ins.base == &vtil::ins::jmp || ins.base == &vtil::ins::vexit);
		ins.operands = { next_pcode };
	}

	logger::log<logger::CON_BLU>("lift handler 0x%llx\n", va);
	vtil::basic_block* tmd_insn_block = block->fork(next_pcode);
	for (;;)
	{
		// lift x86 -> VTIL
		logger::log<logger::CON_BLU>("lift native block 0x%llx\n", va);
		basic_block* native_block = this->lift_native_block(va);
		fassert(native_block->is_complete());


		// then run
		tmd_insn_block = this->run_basic_block(tmd_insn_block, native_block);
		fassert(tmd_insn_block->is_complete());

		if (!native_block->empty())
		{
			const vtil::instruction& ins = native_block->back();
			if (ins.base == &vtil::ins::vexit)
			{
				// lifted handler successfully perhaps
				break;
			}
		}

		// unroll [jmp imm]
		fassert(!tmd_insn_block->empty());
		const vtil::instruction& ins = tmd_insn_block->back();
		fassert(ins.base == &vtil::ins::jmp && ins.operands[0].is_immediate());
		va = ins.operands[0].imm().u64;
		tmd_insn_block->pop_back();
	}

	// optimize away temp variables
	/*vtil::optimizer::exhaust_pass<
		vtil::optimizer::fast_local_dead_code_elimination_pass,
		vtil::optimizer::gpr_elimination_pass,
		vtil::optimizer::fast_reg_propagation_pass,
		vtil::optimizer::fast_mem_propagation_pass,
		vtil::optimizer::collective_local_pass
	>{}(new_block, false);*/

	// idk if this is best at least works i guess...
	using namespace vtil::optimizer;
	/*combine_pass<
		stack_pinning_pass,
		istack_ref_substitution_pass,
		stack_propagation_pass,
		exhaust_pass<gpr_elimination_pass, fast_local_dead_code_elimination_pass>,
		symbolic_rewrite_pass<true>,
		exhaust_pass<gpr_elimination_pass, fast_local_dead_code_elimination_pass, local_pass<mov_propagation_pass>, register_renaming_pass>
	>{}(new_block, false);*/

	// memory state
	/*for (auto it = this->m_global_context->begin(); it != this->m_global_context->end(); ++it)
	{
		symbolic::expression;
		auto entry = *it;
		logger::log("[%s]=%s\n", entry.first.to_string(), entry.second->to_string());
	}*/

	return tmd_insn_block;
}