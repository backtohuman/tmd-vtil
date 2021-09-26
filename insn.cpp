#include "pch.h"

#include "insn.hpp"

x86_basic_block::x86_basic_block()
{
	leader = vtil::invalid_vip;
	next = vtil::invalid_vip;
}
x86_basic_block::x86_basic_block(const x86_basic_block& source)
{
	fassert(source.amd64_instructions.empty());
	this->leader = source.leader;
	this->next = source.next;
}

bool x86_basic_block::contains(uint64_t vip) const
{
	if (leader == vtil::invalid_vip || next == vtil::invalid_vip)
		return false;
	return leader <= vip && vip < next;
}