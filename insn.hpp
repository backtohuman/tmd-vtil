#pragma once

#include <vtil/arch>


// wrapper for vtil::amd64::instruction
struct noncopyable_insn
{
	using insn_t = vtil::amd64::instruction;

	std::set<uint64_t> alive_eflags;
	std::vector<insn_t> insn;

	// noncopyable
	noncopyable_insn(const noncopyable_insn&) = delete;
	noncopyable_insn& operator=(const noncopyable_insn&) = delete;

	// constructors
	noncopyable_insn(std::vector<insn_t>&& v) : insn(std::move(v)) { }
	noncopyable_insn(noncopyable_insn&& s) : insn(std::move(s.insn)), alive_eflags(std::move(s.alive_eflags)) { }

	// operators
	operator const insn_t& () const
	{
		fassert(insn.size() == 1);
		return insn[0];
	}
	const insn_t* operator->() const
	{
		fassert(insn.size() == 1);
		return &insn[0];
	}

	//
	bool is_valid() const
	{
		return this->insn.size() == 1;
	}
};
static_assert(std::is_copy_assignable<noncopyable_insn>::value == false, "");


#define basic_block_ctx(block) block->context.get<x86_basic_block>()


struct x86_basic_block
{
	uint64_t leader, next;

	// <vip, instruction_iterator>
	std::map<uint64_t, vtil::il_const_iterator> pos;

	//
	std::list<noncopyable_insn> amd64_instructions;

	x86_basic_block();
	x86_basic_block(const x86_basic_block& source);
	x86_basic_block& operator=(const x86_basic_block&) = delete;

	bool contains(uint64_t vip) const;
};