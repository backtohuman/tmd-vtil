#include "pch.h"

#include "AbstractStream.hpp"

AbstractStream::AbstractStream(bool x86_64)
{
	this->m_x86_64 = x86_64;
}
AbstractStream::~AbstractStream()
{
}

noncopyable_insn AbstractStream::next()
{
	constexpr size_t max_size = 16;
	uint8_t buf[max_size];
	const uint64_t address = this->pos();
	const size_t readBytes = this->read(buf, max_size);
	noncopyable_insn insn = vtil::amd64::disasm(buf, address);
	this->seek(insn->address + insn->bytes.size());
	return insn;
}